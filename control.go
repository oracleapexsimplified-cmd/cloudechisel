package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// The root-owned VPN process listens on this socket. It is chowned to the
// user who launched it (via pkexec/sudo), so only that user (and root) can
// send "stop". It doubles as a single-instance guard.
const controlSock = "/run/chiselvpn.sock"

func sendControl(cmd string) error {
	c, err := net.DialTimeout("unix", controlSock, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintln(c, cmd); err != nil {
		return err
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(reply) != "ok" {
		return fmt.Errorf("unexpected reply %q", strings.TrimSpace(reply))
	}
	return nil
}

func startControl(cancel context.CancelFunc) (func(), error) {
	_ = os.Remove(controlSock) // stale socket from a crashed run
	l, err := net.Listen("unix", controlSock)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(controlSock, 0o600)
	if u := invokingUser(); u != nil {
		if uid, err := strconv.Atoi(u.Uid); err == nil {
			_ = os.Chown(controlSock, uid, -1)
		}
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				line, _ := bufio.NewReader(c).ReadString('\n')
				switch strings.TrimSpace(line) {
				case "ping":
					fmt.Fprintln(c, "ok")
				case "stop":
					fmt.Fprintln(c, "ok")
					cancel()
				}
			}(c)
		}
	}()
	return func() { l.Close(); _ = os.Remove(controlSock) }, nil
}
