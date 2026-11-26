package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/MichaelBMF/bifrost/internal/client"
)

// clientChannel implements `bifrost client channel`: it opens a channel in message
// mode and connects it to stdin and stdout, one message per line. bifrost does not
// look into the messages; for an mqtt service they are JSON operations, e.g.
//
//	echo '{"op":"pub","id":1,"topic":"midgard/tg/command","payload":{"action":"open"}}' |
//	  bifrost client channel -state phone -service midgard
//
// It ends when the channel closes, or -linger after stdin has ended.
func clientChannel(c *client.Client, service string, linger time.Duration) error {
	if service == "" {
		return errors.New("specify -service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	ch, err := c.OpenChannel(ctx, service)
	cancel()
	if err != nil {
		return err
	}
	defer ch.Close()

	recvErr := make(chan error, 1)
	go func() {
		out := bufio.NewWriter(os.Stdout)
		for {
			msg, err := ch.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			out.Write(msg)
			out.WriteByte('\n')
			out.Flush()
		}
	}()

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<10), 64<<10)
	for in.Scan() {
		if len(in.Bytes()) == 0 {
			continue
		}
		if err := ch.Send(in.Bytes()); err != nil {
			return fmt.Errorf("send: %w", err)
		}
	}
	if err := in.Err(); err != nil {
		return err
	}
	select {
	case err := <-recvErr:
		return fmt.Errorf("channel closed: %w", err)
	case <-time.After(linger):
		return nil
	}
}
