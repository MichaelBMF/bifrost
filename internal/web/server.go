package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"rsc.io/qr"
)

//go:embed assets
var assets embed.FS

// PairingValidity mirrors the agent's pairing window.
const PairingValidity = 5 * time.Minute

var deviceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)

type session struct {
	user    string
	csrf    string
	expires time.Time
}

type Server struct {
	cfg   *Config
	admin *adminClient
	tmpl  *template.Template
	// dummyHash keeps the login timing the same for unknown users.
	dummyHash []byte

	mu       sync.Mutex
	sessions map[string]*session
	limiters map[string]*rate.Limiter
}

func New(cfg *Config) (*Server, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"join":       strings.Join,
		"hasService": func(list []string, s string) bool { return slices.Contains(list, s) },
	}).ParseFS(assets, "assets/*.html")
	if err != nil {
		return nil, err
	}
	dummy, _ := bcrypt.GenerateFromPassword([]byte("not-a-password"), bcrypt.DefaultCost)
	return &Server{
		cfg:       cfg,
		admin:     newAdminClient(cfg.Admin),
		tmpl:      tmpl,
		dummyHash: dummy,
		sessions:  map[string]*session{},
		limiters:  map[string]*rate.Limiter{},
	}, nil
}

func (s *Server) cookieName() string {
	if s.cfg.TLS.Mode == "off" {
		return "hlidskjalf_session"
	}
	return "__Host-hlidskjalf"
}

// Handler returns the HTTP handler with all routes and security headers.
func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "assets/static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.auth(s.logout))
	mux.HandleFunc("GET /{$}", s.auth(s.devicesPage))
	mux.HandleFunc("POST /pair", s.auth(s.pair))
	mux.HandleFunc("GET /pair", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusSeeOther) })
	mux.HandleFunc("POST /revoke", s.auth(s.revoke))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// MARK: sessions

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) currentSession(r *http.Request) *session {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[c.Value]
	if sess == nil || time.Now().After(sess.expires) {
		delete(s.sessions, c.Value)
		return nil
	}
	return sess
}

type authedHandler func(http.ResponseWriter, *http.Request, *session)

// auth requires a session; for POST requests also a matching CSRF token.
func (s *Server) auth(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.currentSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.csrf)) != 1 {
				http.Error(w, "invalid form token, reload the page", http.StatusForbidden)
				return
			}
		}
		h(w, r, sess)
	}
}

func (s *Server) limiter(r *http.Request) *rate.Limiter {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.limiters[ip]
	if l == nil {
		// 5 attempts, then one every 12 seconds.
		l = rate.NewLimiter(rate.Every(12*time.Second), 5)
		s.limiters[ip] = l
	}
	return l
}

// MARK: pages

type page struct {
	Title    string
	User     string
	CSRF     string
	Error    string
	Notice   string
	Devices  []Device
	Services []string
	Pairing  *pairing
	Form     pairForm
}

type pairing struct {
	Name     string
	Code     string
	QR       template.URL
	Services []string
	User     string
	Expires  time.Time
}

type pairForm struct {
	Name     string
	User     string
	Services []string
}

func (s *Server) render(w http.ResponseWriter, name string, status int, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, p); err != nil {
		log.Printf("hlidskjalf: template %s: %v", name, err)
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.currentSession(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", http.StatusOK, page{Title: "Anmelden"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if !s.limiter(r).Allow() {
		s.render(w, "login.html", http.StatusTooManyRequests, page{Title: "Anmelden", Error: "Zu viele Versuche. Bitte kurz warten."})
		return
	}
	name := strings.TrimSpace(r.PostFormValue("user"))
	pass := r.PostFormValue("password")
	hash := s.dummyHash
	idx := slices.IndexFunc(s.cfg.Users, func(u User) bool { return u.Name == name })
	if idx >= 0 {
		hash = []byte(s.cfg.Users[idx].PasswordHash)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(pass)) != nil || idx < 0 {
		log.Printf("hlidskjalf: failed login for %q from %s", name, r.RemoteAddr)
		s.render(w, "login.html", http.StatusUnauthorized, page{Title: "Anmelden", Error: "Benutzername oder Passwort falsch."})
		return
	}
	token := randomToken()
	ttl := time.Duration(s.cfg.SessionHours) * time.Hour
	s.mu.Lock()
	for k, v := range s.sessions { // drop expired sessions
		if time.Now().After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[token] = &session{user: name, csrf: randomToken(), expires: time.Now().Add(ttl)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: token, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: s.cfg.TLS.Mode != "off", SameSite: http.SameSiteStrictMode,
	})
	log.Printf("hlidskjalf: %q logged in from %s", name, r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ *session) {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.TLS.Mode != "off", SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) basePage(sess *session) page {
	return page{Title: "Geräte", User: sess.user, CSRF: sess.csrf, Services: s.cfg.Services,
		Form: pairForm{Services: s.cfg.Services[:1]}}
}

func (s *Server) withDevices(p *page) {
	devices, err := s.admin.Devices()
	if err != nil {
		p.Error = err.Error()
		return
	}
	for i := range devices {
		devices[i].Protected = s.cfg.isProtected(devices[i].Name)
	}
	p.Devices = devices
}

func (s *Server) devicesPage(w http.ResponseWriter, r *http.Request, sess *session) {
	p := s.basePage(sess)
	switch r.URL.Query().Get("ok") {
	case "revoked":
		p.Notice = "Gerät widerrufen."
	}
	s.withDevices(&p)
	s.render(w, "devices.html", http.StatusOK, p)
}

func (s *Server) pair(w http.ResponseWriter, r *http.Request, sess *session) {
	p := s.basePage(sess)
	form := pairForm{
		Name: strings.ToLower(strings.TrimSpace(r.PostFormValue("name"))),
		User: strings.TrimSpace(r.PostFormValue("user")),
	}
	for _, svc := range r.Form["services"] {
		if slices.Contains(s.cfg.Services, svc) && !slices.Contains(form.Services, svc) {
			form.Services = append(form.Services, svc)
		}
	}
	p.Form = form
	err := func() error {
		if !deviceNameRe.MatchString(form.Name) {
			return errors.New("Gerätename: nur a–z, 0–9, Punkt, Binde- und Unterstrich, max. 48 Zeichen.")
		}
		if len(form.Services) == 0 {
			return errors.New("Mindestens einen Service auswählen.")
		}
		if len(form.User) > 64 {
			return errors.New("Benutzername ist zu lang.")
		}
		devices, err := s.admin.Devices()
		if err != nil {
			return err
		}
		for _, d := range devices {
			if d.Name == form.Name {
				return fmt.Errorf("Ein Gerät %q gibt es schon. Erst widerrufen oder anderen Namen wählen.", form.Name)
			}
		}
		code, err := s.admin.Pair(form.Name, form.Services, form.User)
		if err != nil {
			return err
		}
		img, err := qrDataURL(code)
		if err != nil {
			return err
		}
		p.Pairing = &pairing{Name: form.Name, Code: code, QR: img, Services: form.Services,
			User: form.User, Expires: time.Now().Add(PairingValidity)}
		log.Printf("hlidskjalf: %q opened pairing for %q (services %v, user %q)", sess.user, form.Name, form.Services, form.User)
		return nil
	}()
	status := http.StatusOK
	if err != nil {
		p.Error = err.Error()
		status = http.StatusBadRequest
	}
	s.withDevices(&p)
	s.render(w, "devices.html", status, p)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PostFormValue("name")
	p := s.basePage(sess)
	err := func() error {
		if s.cfg.isProtected(name) {
			return fmt.Errorf("%q ist geschützt und kann hier nicht widerrufen werden.", name)
		}
		if r.PostFormValue("confirm") != name {
			return fmt.Errorf("Zum Widerrufen den Gerätenamen %q genau eintippen.", name)
		}
		return s.admin.Revoke(name)
	}()
	if err != nil {
		p.Error = err.Error()
		s.withDevices(&p)
		s.render(w, "devices.html", http.StatusBadRequest, p)
		return
	}
	log.Printf("hlidskjalf: %q revoked %q", sess.user, name)
	http.Redirect(w, r, "/?ok=revoked", http.StatusSeeOther)
}

// qrDataURL renders the code as an SVG QR image (data: URL, no external requests).
func qrDataURL(text string) (template.URL, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := c.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, n, n)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#0B1426" d="`, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return template.URL("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(b.String()))), nil
}
