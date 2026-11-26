// bifrost: home lab relay prototype (v2).
//
//	bifrost heimdall -config heimdall.json   (relay on the VPS)
//	bifrost asgard   -config asgard.json     (agent in the home lab)
//	bifrost hlidskjalf -config hlidskjalf.json (web UI for devices, next to asgard)
//	bifrost hlidskjalf -hash                   (bcrypt hash for a UI password)
//	bifrost pair     -admin 127.0.0.1:7070 -name iphone -services mqtt,ha [-user alice]
//	bifrost revoke   -admin 127.0.0.1:7070 -name iphone
//	bifrost devices  -admin 127.0.0.1:7070
//	bifrost client pair    -state phone -code bifrost1:... [-user alice] [-device-name "Alice's iPhone"]
//	bifrost client forward -state phone -L mqtt=127.0.0.1:11883 [-L ha=127.0.0.1:18123]
//	bifrost client mqtt pub -state phone -service midgard -t midgard/tg/command -m '{"action":"open"}'
//	bifrost client mqtt sub -state phone -service midgard -t 'midgard/#'
//	bifrost version
//	bifrost upgrade [-check] [-to v0.2.0]       (install the latest signed release)
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
	"github.com/MichaelBMF/bifrost/internal/web"
	"github.com/mdp/qrterminal/v3"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

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
	case "version", "-version", "--version":
		fmt.Println(version)
	case "upgrade":
		check(upgrade(args))
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
	case "hlidskjalf":
		cfgPath := fs.String("config", "hlidskjalf.json", "config file")
		hash := fs.Bool("hash", false, "read a password from the terminal and print its bcrypt hash")
		fs.Parse(args)
		if *hash {
			h, err := web.HashPasswordInteractive()
			check(err)
			fmt.Println(h)
			return
		}
		cfg, err := web.LoadConfig(*cfgPath)
		check(err)
		check(web.Run(cfg))
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
		if sub == "mqtt" {
			clientMQTT(args[1:])
			return
		}
		state := fs.String("state", "phone", "base name for keys and state")
		code := fs.String("code", "", "pairing code (bifrost1:...)")
		user := fs.String("user", "", "pair: app user name sent to the agent (optional)")
		devName := fs.String("device-name", "", "pair: device name sent to the agent (optional)")
		var fwd multi
		fs.Var(&fwd, "L", "service=address, repeatable")
		fs.Parse(args[1:])
		c, err := client.Open(*state)
		check(err)
		switch sub {
		case "pair":
			res, err := c.Pair(*code, client.PairOptions{User: *user, DeviceName: *devName})
			check(err)
			fmt.Printf("Paired as %q. Services: %v\n", res.Name, res.Services)
			if res.User != "" || res.DeviceName != "" {
				fmt.Printf("User: %q, device name: %q\n", res.User, res.DeviceName)
			}
			fmt.Printf("Device fingerprint: %s\nAgent fingerprint: %s\n", res.DeviceFP, res.AgentFP)
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
				log.Printf("warning: every process on this machine can use %s to reach %q as this device; for MQTT use `bifrost client mqtt`", addr, svc)
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
	fmt.Fprintln(os.Stderr, `bifrost heimdall|asgard|hlidskjalf|pair|revoke|devices|client pair|client forward|client mqtt pub|sub|version|upgrade  (details: README.md)`)
	os.Exit(2)
}
