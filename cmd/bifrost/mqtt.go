package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/MichaelBMF/bifrost/internal/client"
	"github.com/MichaelBMF/bifrost/internal/mqttc"
)

// clientMQTT implements `bifrost client mqtt pub|sub`: MQTT inside this process,
// through the tunnel, without a local port.
//
//	bifrost client mqtt pub -state phone [-service mqtt] -t topic -m message [-q 1] [-r]
//	bifrost client mqtt sub -state phone [-service mqtt] -t filter [-t filter...] [-q 1] [-C n] [-W sec]
//
// For a plain MQTT service the broker login comes from -username and the environment
// variable BIFROST_MQTT_PASSWORD (not a flag, so it does not show up in ps). An MQTT
// gateway needs neither.
func clientMQTT(args []string) {
	if len(args) < 1 || (args[0] != "pub" && args[0] != "sub") {
		fmt.Fprintln(os.Stderr, "usage: bifrost client mqtt pub|sub -state ... -t ...")
		os.Exit(2)
	}
	mode := args[0]
	fs := flag.NewFlagSet("client mqtt "+mode, flag.ExitOnError)
	state := fs.String("state", "phone", "base name for keys and state")
	service := fs.String("service", "mqtt", "service or MQTT gateway to connect to")
	username := fs.String("username", "", "broker user for a plain MQTT service (password: $BIFROST_MQTT_PASSWORD)")
	clientID := fs.String("id", "bifrost-cli", "MQTT client ID")
	var topics multi
	fs.Var(&topics, "t", "topic (pub) or filter (sub, repeatable)")
	message := fs.String("m", "", "pub: message; - reads it from stdin")
	qos := fs.Int("q", 0, "QoS 0 or 1")
	retain := fs.Bool("r", false, "pub: retain the message")
	count := fs.Int("C", 0, "sub: exit after this many messages (0 = run until interrupted)")
	wait := fs.Int("W", 0, "sub: exit with an error after this many seconds without the -C messages (0 = no limit)")
	fs.Parse(args[1:])
	if len(topics) == 0 || (mode == "pub" && len(topics) != 1) {
		log.Fatal("pub needs exactly one -t topic, sub at least one -t filter")
	}

	c, err := client.Open(*state)
	check(err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	conn, err := c.DialServiceContext(ctx, *service)
	cancel()
	check(err)

	msgs := make(chan mqttc.Message, 64)
	closed := make(chan error, 1)
	s, err := mqttc.Connect(conn, mqttc.Options{
		ClientID: *clientID, Username: *username, Password: os.Getenv("BIFROST_MQTT_PASSWORD"),
		OnMessage: func(m mqttc.Message) { msgs <- m },
		OnClose:   func(err error) { closed <- err },
	})
	check(err)
	defer s.Close()

	if mode == "pub" {
		payload := []byte(*message)
		if *message == "-" {
			payload, err = io.ReadAll(os.Stdin)
			check(err)
		}
		if err := s.Publish(topics[0], payload, *qos, *retain); err != nil {
			s.Close()
			log.Fatal(err)
		}
		return
	}

	for _, f := range topics {
		if err := s.Subscribe(f, *qos); err != nil {
			s.Close()
			log.Fatal(err)
		}
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	var timeout <-chan time.Time
	if *wait > 0 {
		timeout = time.After(time.Duration(*wait) * time.Second)
	}
	for n := 0; *count == 0 || n < *count; n++ {
		select {
		case m := <-msgs:
			fmt.Printf("%s %s\n", m.Topic, strings.TrimRight(string(m.Payload), "\n"))
		case err := <-closed:
			if err == nil {
				err = errors.New("session closed")
			}
			log.Fatal(err)
		case <-timeout:
			s.Close()
			log.Fatalf("timeout after %d s", *wait)
		case <-interrupt:
			return
		}
	}
}
