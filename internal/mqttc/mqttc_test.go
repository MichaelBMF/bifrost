package mqttc_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/MichaelBMF/bifrost/internal/mqttc"
	"github.com/MichaelBMF/bifrost/internal/mqttc/mqtttest"
)

func connect(t *testing.T, b *mqtttest.Broker, opts mqttc.Options) *mqttc.Session {
	t.Helper()
	c, err := net.Dial("tcp", b.Addr())
	if err != nil {
		t.Fatal(err)
	}
	s, err := mqttc.Connect(c, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func recv(t *testing.T, ch <-chan mqttc.Message) mqttc.Message {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message")
	}
	return mqttc.Message{}
}

func TestPublishSubscribe(t *testing.T) {
	b := mqtttest.Start(t)
	b.Publish("home/old", []byte("retained"), true)

	msgs := make(chan mqttc.Message, 16)
	var s *mqttc.Session
	s = connect(t, b, mqttc.Options{ClientID: "a", OnMessage: func(m mqttc.Message) {
		msgs <- m
		if m.Topic == "home/ping" {
			// Publishing from the callback must not deadlock.
			if err := s.Publish("home/pong", m.Payload, 1, false); err != nil {
				t.Error(err)
			}
		}
	}})
	if err := s.Subscribe("home/#", 1); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, msgs); m.Topic != "home/old" || string(m.Payload) != "retained" || !m.Retained {
		t.Fatalf("retained message: %+v", m)
	}
	for qos := range 2 {
		if err := s.Publish("home/x", []byte{byte(qos)}, qos, false); err != nil {
			t.Fatal(err)
		}
		if m := recv(t, msgs); m.Topic != "home/x" || m.Payload[0] != byte(qos) || m.Retained {
			t.Fatalf("qos %d: %+v", qos, m)
		}
	}
	b.Publish("home/ping", []byte("hi"), false)
	recv(t, msgs)
	if m := recv(t, msgs); m.Topic != "home/pong" || string(m.Payload) != "hi" {
		t.Fatalf("pong: %+v", m)
	}

	if err := s.Unsubscribe("home/#"); err != nil {
		t.Fatal(err)
	}
	b.Publish("home/x", []byte("late"), false)
	select {
	case m := <-msgs:
		t.Fatalf("message after unsubscribe: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}

	for _, bad := range []func() error{
		func() error { return s.Publish("home/+", nil, 0, false) },
		func() error { return s.Publish("", nil, 0, false) },
		func() error { return s.Publish("home/x", nil, 2, false) },
		func() error { return s.Subscribe("home/#/x", 0) },
		func() error { return s.Subscribe("home/#", 2) },
	} {
		if bad() == nil {
			t.Error("invalid call accepted")
		}
	}
}

func TestCloseAndConnectionLoss(t *testing.T) {
	b := mqtttest.Start(t)
	closed := make(chan error, 1)
	s := connect(t, b, mqttc.Options{OnClose: func(err error) { closed <- err }})
	s.Close()
	if err := <-closed; err != nil {
		t.Fatalf("OnClose after Close: %v", err)
	}
	if err := s.Publish("a", nil, 0, false); !errors.Is(err, mqttc.ErrClosed) {
		t.Fatalf("publish after close: %v", err)
	}
	s.Close() // second Close is a no-op

	s2 := connect(t, b, mqttc.Options{OnClose: func(err error) { closed <- err }})
	b.DropAll()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("connection loss must report an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnClose not called after connection loss")
	}
	if s2.Err() == nil {
		t.Fatal("Err must be set after connection loss")
	}
	if err := s2.Subscribe("a", 0); !errors.Is(err, mqttc.ErrClosed) {
		t.Fatalf("subscribe after loss: %v", err)
	}
}

func TestKeepAlive(t *testing.T) {
	b := mqtttest.Start(t)
	s := connect(t, b, mqttc.Options{KeepAlive: time.Second})
	time.Sleep(3 * time.Second) // several PINGREQ/PINGRESP rounds
	if s.Err() != nil {
		t.Fatalf("session died: %v", s.Err())
	}

	// A peer that stops answering is detected after 1.5 keep-alive intervals.
	a, peer := net.Pipe()
	go func() {
		buf := make([]byte, 64)
		peer.Read(buf)                    // CONNECT
		peer.Write([]byte{0x20, 2, 0, 0}) // CONNACK
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { peer.Close() })
	dead, err := mqttc.Connect(a, mqttc.Options{KeepAlive: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-dead.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("silent peer not detected")
	}
}

func TestCredentials(t *testing.T) {
	b := mqtttest.Start(t)
	connect(t, b, mqttc.Options{Username: "monitor", Password: "secret"})
	connect(t, b, mqttc.Options{})
	if u := b.Users(); len(u) != 2 || u[0] != "monitor" || u[1] != "" {
		t.Fatalf("broker users: %v", u)
	}
}

func TestConnectRefused(t *testing.T) {
	a, peer := net.Pipe()
	go func() {
		buf := make([]byte, 64)
		peer.Read(buf)
		peer.Write([]byte{0x20, 2, 0, 5}) // not authorized
	}()
	if _, err := mqttc.Connect(a, mqttc.Options{}); err == nil {
		t.Fatal("refused CONNACK must fail")
	}
}
