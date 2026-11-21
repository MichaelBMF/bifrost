// bifrost: home lab relay prototype (v2).
//
//	bifrost heimdall -config heimdall.json   (relay on the VPS)
//	bifrost asgard   -config asgard.json     (agent in the home lab)
//	bifrost pair     -admin 127.0.0.1:7070 -name iphone -services mqtt,ha [-user alice]
//	bifrost revoke   -admin 127.0.0.1:7070 -name iphone
//	bifrost devices  -admin 127.0.0.1:7070
//	bifrost client pair    -state phone -code bifrost1:...
//	bifrost client forward -state phone -L mqtt=127.0.0.1:11883 [-L ha=127.0.0.1:18123]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/MichaelBMF/bifrost/internal/agent"
	"github.com/MichaelBMF/bifrost/internal/client"
	"github.com/MichaelBMF/bifrost/internal/relay"
	"github.com/mdp/qrterminal/v3"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "heimdall":
		cfgPath := fs.String("config", "heimdall.json", "config file")
		fs.Parse(args)
		cfg, err := relay.LoadConfig(*cfgPath)
		check(err)
		check(relay.New(cfg).Run())
	case "asgard":
		cfgPath := fs.String("config", "asgard.json", "config file")
		fs.Parse(args)
		cfg, err := agent.LoadConfig(*cfgPath)
		check(err)
		a, err := agent.New(cfg)
		check(err)
		check(a.Run())
	case "pair", "revoke", "devices":
		admin := fs.String("admin", "127.0.0.1:7070", "agent admin address")
		name := fs.String("name", "", "device name")
		svcs := fs.String("services", "", "allowed services, comma-separated")
		user := fs.String("user", "", "pair: bind the pairing to this app user name (optional)")
		fs.Parse(args)
		base := "http://" + *admin
		v := url.Values{"name": {*name}, "services": {*svcs}}
		if *user != "" {
			v.Set("user", *user)
		}
		q := v.Encode()
		var resp *http.Response
		var err error
		if cmd == "devices" {
			resp, err = http.Get(base + "/devices")
		} else {
			resp, err = http.Post(base+"/"+cmd+"?"+q, "", nil)
		}
		check(err)
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			log.Fatalf("error: %s", strings.TrimSpace(string(body)))
		}
		if cmd == "pair" {
			var out struct{ Code string }
			check(json.Unmarshal(body, &out))
			qrterminal.GenerateHalfBlock(out.Code, qrterminal.L, os.Stdout)
			fmt.Println(out.Code)
			fmt.Println("Valid for 5 minutes, single use.")
		} else {
			fmt.Print(string(body))
		}
	case "client":
		if len(args) < 1 {
			usage()
		}
		sub := args[0]
		state := fs.String("state", "phone", "base name for keys and state")
		code := fs.String("code", "", "pairing code (bifrost1:...)")
		var fwd multi
		fs.Var(&fwd, "L", "service=address, repeatable")
		fs.Parse(args[1:])
		c, err := client.Open(*state)
		check(err)
		switch sub {
		case "pair":
			check(c.Pair(*code))
		case "forward":
			if len(fwd) == 0 {
				log.Fatal("specify at least one -L service=address")
			}
			errc := make(chan error)
			for _, f := range fwd {
				svc, addr, ok := strings.Cut(f, "=")
				if !ok {
					log.Fatalf("invalid: %s", f)
				}
				go func() { errc <- c.Forward(svc, addr) }()
			}
			check(<-errc)
		default:
			usage()
		}
	default:
		usage()
	}
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `bifrost heimdall|asgard|pair|revoke|devices|client pair|client forward  (details: README.md)`)
	os.Exit(2)
}
