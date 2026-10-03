// chiselvpn: Chisel SOCKS5 + badvpn-tun2socks + UDPGW VPN client with
// persistent, editable settings and an optional UDP/53 (DNS) bypass.
//
// Usage:
//
//	chiselvpn               GUI window (same as: chiselvpn gui)
//	chiselvpn menu          terminal menu
//	chiselvpn stop          stop a running session
//	chiselvpn up            connect (re-runs itself with sudo if needed)
//	chiselvpn show          print current settings
//	chiselvpn set k v ...   change settings (also accepts k=v)
//	chiselvpn edit          step through every setting (Enter keeps current)
//	chiselvpn reset         restore defaults
//	chiselvpn keys          list setting names
//	chiselvpn path          print config file location
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ----------------------------------------------------------------------------
// Settings
// ----------------------------------------------------------------------------

type Config struct {
	ChiselDomain string `json:"chisel_domain" desc:"Chisel server domain"`
	ChiselPort   int    `json:"chisel_port" desc:"Chisel server HTTPS port"`
	ChiselAuth   string `json:"chisel_auth" desc:"Chisel auth user:pass (optional, '-' clears)"`
	SocksPort    int    `json:"socks_port" desc:"Local SOCKS5 port"`
	UdpgwPort    int    `json:"udpgw_port" desc:"UDPGW port (local and remote)"`
	UdpgwMaxConn int    `json:"udpgw_max_connections" desc:"UDPGW max connections"`
	UdpgwBufSize int    `json:"udpgw_buffer_size" desc:"UDPGW connection buffer size"`
	TunDev       string `json:"tun_dev" desc:"TUN device name"`
	TunIP        string `json:"tun_ip" desc:"TUN interface IP"`
	TunPeerIP    string `json:"tun_netif_ip" desc:"tun2socks virtual netif IP"`
	TunPrefix    int    `json:"tun_prefix" desc:"TUN subnet prefix length"`
	MTU          int    `json:"mtu" desc:"TUN MTU"`
	DisableIPv6  bool   `json:"disable_ipv6" desc:"Disable IPv6 system-wide while connected (true/false)"`
	DNSBypass    bool   `json:"dns_bypass" desc:"Send UDP/53 out the physical NIC (true/false)"`
	DNSMark      string `json:"dns_mark" desc:"fwmark used for DNS bypass"`
	DNSTable     int    `json:"dns_table" desc:"Routing table for DNS bypass"`
	DNSRulePrio  int    `json:"dns_rule_prio" desc:"ip rule priority for DNS bypass"`
	LogLevel     string `json:"log_level" desc:"tun2socks log level (none|error|warning|notice|info|debug)"`
	ChiselBin    string `json:"chisel_bin" desc:"chisel binary"`
	Tun2socksBin string `json:"tun2socks_bin" desc:"badvpn-tun2socks binary"`
}

func DefaultConfig() Config {
	return Config{
		ChiselDomain: "example_url.com",
		ChiselPort:   443,
		SocksPort:    1080,
		UdpgwPort:    7300,
		UdpgwMaxConn: 2000,
		UdpgwBufSize: 128,
		TunDev:       "tun0",
		TunIP:        "198.18.0.1",
		TunPeerIP:    "198.18.0.2",
		TunPrefix:    15,
		MTU:          1400,
		DisableIPv6:  true,
		DNSBypass:    true,
		DNSMark:      "0x53",
		DNSTable:     53,
		DNSRulePrio:  100,
		LogLevel:     "error",
		ChiselBin:    "chisel",
		Tun2socksBin: "badvpn-tun2socks",
	}
}

var devRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

func (c Config) Validate() error {
	port := func(n int, name string) error {
		if n < 1 || n > 65535 {
			return fmt.Errorf("%s must be 1-65535", name)
		}
		return nil
	}
	if c.ChiselDomain == "" || strings.ContainsAny(c.ChiselDomain, " /:@") {
		return errors.New("chisel_domain must be a bare hostname")
	}
	for _, p := range []struct {
		n int
		s string
	}{{c.ChiselPort, "chisel_port"}, {c.SocksPort, "socks_port"}, {c.UdpgwPort, "udpgw_port"}} {
		if err := port(p.n, p.s); err != nil {
			return err
		}
	}
	if !devRe.MatchString(c.TunDev) {
		return errors.New("tun_dev must be 1-15 chars of [A-Za-z0-9_.-]")
	}
	for _, s := range []string{c.TunIP, c.TunPeerIP} {
		if ip := net.ParseIP(s); ip == nil || ip.To4() == nil {
			return fmt.Errorf("%q is not a valid IPv4 address", s)
		}
	}
	if c.TunPrefix < 8 || c.TunPrefix > 30 {
		return errors.New("tun_prefix must be 8-30")
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return errors.New("mtu must be 576-9000")
	}
	if c.UdpgwMaxConn < 1 || c.UdpgwBufSize < 1 {
		return errors.New("udpgw limits must be positive")
	}
	if _, err := strconv.ParseUint(c.DNSMark, 0, 32); err != nil {
		return errors.New("dns_mark must be a number like 0x53")
	}
	if c.DNSTable < 1 || c.DNSTable > 252 {
		return errors.New("dns_table must be 1-252")
	}
	if c.DNSRulePrio < 1 || c.DNSRulePrio > 32765 {
		return errors.New("dns_rule_prio must be 1-32765")
	}
	switch c.LogLevel {
	case "none", "error", "warning", "notice", "info", "debug":
	default:
		return errors.New("log_level must be none|error|warning|notice|info|debug")
	}
	if c.ChiselBin == "" || c.Tun2socksBin == "" {
		return errors.New("binary names must not be empty")
	}
	return nil
}

func (c *Config) Set(key, val string) error {
	rv := reflect.ValueOf(c).Elem()
	rt := rv.Type()
	val = strings.TrimSpace(val)
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Tag.Get("json") != key {
			continue
		}
		f := rv.Field(i)
		switch f.Kind() {
		case reflect.String:
			if val == "-" {
				val = ""
			}
			f.SetString(val)
		case reflect.Int:
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("%s must be a number", key)
			}
			f.SetInt(int64(n))
		case reflect.Bool:
			b, err := strconv.ParseBool(val)
			if err != nil {
				return fmt.Errorf("%s must be true or false", key)
			}
			f.SetBool(b)
		}
		return nil
	}
	return fmt.Errorf("unknown setting %q (run: chiselvpn keys)", key)
}

// trySet applies a change only if the resulting config is valid.
func (c *Config) trySet(key, val string) error {
	n := *c
	if err := n.Set(key, val); err != nil {
		return err
	}
	if err := n.Validate(); err != nil {
		return err
	}
	*c = n
	return nil
}

type entry struct{ Key, Desc, Val string }

func (c Config) List() []entry {
	rv := reflect.ValueOf(c)
	rt := rv.Type()
	var out []entry
	for i := 0; i < rt.NumField(); i++ {
		key := rt.Field(i).Tag.Get("json")
		val := fmt.Sprint(rv.Field(i).Interface())
		if key == "chisel_auth" && val != "" {
			val = "********"
		}
		out = append(out, entry{key, rt.Field(i).Tag.Get("desc"), val})
	}
	return out
}

// ----------------------------------------------------------------------------
// Persistence (works the same with or without sudo)
// ----------------------------------------------------------------------------

// invokingUser returns the real user behind sudo/pkexec, or nil.
func invokingUser() *user.User {
	if os.Geteuid() != 0 {
		return nil
	}
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil {
			return u
		}
	}
	if id := os.Getenv("PKEXEC_UID"); id != "" {
		if u, err := user.LookupId(id); err == nil {
			return u
		}
	}
	return nil
}

func configPath() string {
	home := ""
	if u := invokingUser(); u != nil {
		home = u.HomeDir
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, ".config", "chiselvpn", "config.json")
}

func chownToSudoUser(paths ...string) {
	u := invokingUser()
	if u == nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, p := range paths {
		_ = os.Chown(p, uid, gid)
	}
}

func LoadConfig() (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(configPath())
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing %s: %w", configPath(), err)
	}
	return cfg, cfg.Validate()
}

func SaveConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	path := configPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	chownToSudoUser(dir, path)
	return nil
}

// ----------------------------------------------------------------------------
// Process / command helpers
// ----------------------------------------------------------------------------

func sh(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func try(name string, args ...string) { _ = exec.Command(name, args...).Run() }

func sysctlGet(key string) string {
	out, _ := exec.Command("sysctl", "-n", key).Output()
	return strings.TrimSpace(string(out))
}

func sysctlSet(key, val string) error { return sh("sysctl", "-w", key+"="+val) }

type proc struct {
	name   string
	cmd    *exec.Cmd
	exited chan struct{}
	err    error
}

func startProc(name string, args ...string) (*proc, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &proc{name: name, cmd: cmd, exited: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.exited) }()
	return p, nil
}

func (p *proc) stop() {
	select {
	case <-p.exited:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
	case <-time.After(3 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
}

func defaultRoute(skipDev string) (dev, gw string, err error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		dev, gw = "", ""
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				gw = f[i+1]
			case "dev":
				dev = f[i+1]
			}
		}
		if dev != "" && gw != "" && dev != skipDev {
			return dev, gw, nil
		}
	}
	return "", "", errors.New("could not determine default network interface or gateway")
}

// ----------------------------------------------------------------------------
// Connect
// ----------------------------------------------------------------------------

func say(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func reexecWithSudo() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	say("[*] Root is required; re-running with sudo...")
	cmd := exec.Command("sudo", "-E", exe, "up")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func connect(cfg Config) error {
	if os.Geteuid() != 0 {
		return reexecWithSudo()
	}
	needed := []string{"ip", "sysctl", cfg.ChiselBin, cfg.Tun2socksBin}
	if cfg.DNSBypass {
		needed = append(needed, "iptables")
	}
	for _, b := range needed {
		if _, err := exec.LookPath(b); err != nil {
			return fmt.Errorf("required binary not found in PATH: %s", b)
		}
	}

	var undo []func()
	add := func(f func()) { undo = append(undo, f) }
	defer func() {
		say("\n[*] Cleaning up routes, interface, and DNS bypass...")
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		say("[+] Disconnected cleanly.")
	}()

	sigCtx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	if sendControl("ping") == nil {
		return errors.New("another chiselvpn session is already running")
	}
	closeCtl, err := startControl(cancel)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	defer closeCtl()

	// 1. Physical interface + gateway
	dev, gw, err := defaultRoute(cfg.TunDev)
	if err != nil {
		return err
	}
	say("[+] Default Interface: %s", dev)
	say("[+] Default Gateway:   %s", gw)

	rpAllKey := "net.ipv4.conf.all.rp_filter"
	rpDevKey := "net.ipv4.conf." + dev + ".rp_filter"
	oldRPAll, oldRPDev := sysctlGet(rpAllKey), sysctlGet(rpDevKey)

	// 2. Resolve chisel server (IPv4 only, avoids routing loops) and bypass it
	say("[*] Resolving IPv4 addresses for %s...", cfg.ChiselDomain)
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	ips, err := net.DefaultResolver.LookupIP(rctx, "ip4", cfg.ChiselDomain)
	cancel()
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("unable to resolve %s: %v", cfg.ChiselDomain, err)
	}
	for _, ip := range ips {
		cidr := ip.String() + "/32"
		say("[+] Adding bypass route for %s via %s dev %s", ip, gw, dev)
		if err := sh("ip", "route", "replace", cidr, "via", gw, "dev", dev, "metric", "1"); err != nil {
			say("[!] %v", err)
			continue
		}
		add(func() { try("ip", "route", "del", cidr, "via", gw, "dev", dev) })
	}

	// 3. Chisel client
	say("[*] Starting Chisel client...")
	cargs := []string{"client"}
	if cfg.ChiselAuth != "" {
		cargs = append(cargs, "--auth", cfg.ChiselAuth)
	}
	cargs = append(cargs,
		fmt.Sprintf("https://%s:%d", cfg.ChiselDomain, cfg.ChiselPort),
		fmt.Sprintf("%d:socks", cfg.SocksPort),
		fmt.Sprintf("%d:127.0.0.1:%d", cfg.UdpgwPort, cfg.UdpgwPort),
	)
	chisel, err := startProc(cfg.ChiselBin, cargs...)
	if err != nil {
		return fmt.Errorf("starting chisel: %w", err)
	}
	add(chisel.stop)

	socksAddr := fmt.Sprintf("127.0.0.1:%d", cfg.SocksPort)
	say("[*] Waiting for Chisel SOCKS5 proxy on %s...", socksAddr)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", socksAddr, 500*time.Millisecond); err == nil {
			c.Close()
			break
		}
		select {
		case <-chisel.exited:
			return fmt.Errorf("chisel client died unexpectedly: %v", chisel.err)
		case <-ctx.Done():
			return nil
		case <-time.After(500 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("chisel failed to open the SOCKS5 port within 10 seconds")
		}
	}
	say("[+] Chisel SOCKS5 and UDPGW port tunnels active!")

	// 4. TUN interface
	say("[*] Creating TUN interface (%s)...", cfg.TunDev)
	try("ip", "link", "delete", cfg.TunDev)
	if err := sh("ip", "tuntap", "add", "dev", cfg.TunDev, "mode", "tun"); err != nil {
		return err
	}
	add(func() {
		try("ip", "link", "set", cfg.TunDev, "down")
		try("ip", "tuntap", "del", "dev", cfg.TunDev, "mode", "tun")
	})
	if err := sh("ip", "addr", "add", fmt.Sprintf("%s/%d", cfg.TunIP, cfg.TunPrefix), "dev", cfg.TunDev); err != nil {
		return err
	}
	_ = sysctlSet("net.ipv6.conf."+cfg.TunDev+".disable_ipv6", "1")
	if err := sh("ip", "link", "set", cfg.TunDev, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
		return err
	}
	if err := sh("ip", "link", "set", cfg.TunDev, "up"); err != nil {
		return err
	}

	// 5. badvpn-tun2socks with remote UDPGW
	say("[*] Starting badvpn-tun2socks...")
	netmask := net.IP(net.CIDRMask(cfg.TunPrefix, 32)).String()
	t2s, err := startProc(cfg.Tun2socksBin,
		"--tundev", cfg.TunDev,
		"--netif-ipaddr", cfg.TunPeerIP,
		"--netif-netmask", netmask,
		"--socks-server-addr", socksAddr,
		"--udpgw-remote-server-addr", fmt.Sprintf("127.0.0.1:%d", cfg.UdpgwPort),
		"--udpgw-max-connections", strconv.Itoa(cfg.UdpgwMaxConn),
		"--udpgw-connection-buffer-size", strconv.Itoa(cfg.UdpgwBufSize),
		"--loglevel", cfg.LogLevel,
	)
	if err != nil {
		return fmt.Errorf("starting tun2socks: %w", err)
	}
	add(t2s.stop)
	select {
	case <-t2s.exited:
		return fmt.Errorf("tun2socks exited unexpectedly: %v", t2s.err)
	case <-ctx.Done():
		return nil
	case <-time.After(2 * time.Second):
	}

	// 6. DNS bypass: mark UDP/53, route marked packets out the physical NIC
	if cfg.DNSBypass {
		table := strconv.Itoa(cfg.DNSTable)
		prio := strconv.Itoa(cfg.DNSRulePrio)
		say("[*] Setting up UDP/53 bypass (fwmark %s, table %s)...", cfg.DNSMark, table)

		if err := sh("ip", "route", "replace", "default", "via", gw, "dev", dev, "table", table); err != nil {
			return err
		}
		add(func() { try("ip", "route", "flush", "table", table) })

		if err := sh("ip", "rule", "add", "fwmark", cfg.DNSMark, "lookup", table, "priority", prio); err != nil {
			return err
		}
		add(func() { try("ip", "rule", "del", "fwmark", cfg.DNSMark, "lookup", table, "priority", prio) })

		// Skip loopback so a local stub resolver (e.g. 127.0.0.53) still works
		mangle := []string{"-t", "mangle", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-d", "127.0.0.0/8",
			"-j", "MARK", "--set-mark", cfg.DNSMark}
		if err := sh("iptables", append([]string{"-t", "mangle", "-A"}, mangle[2:]...)...); err != nil {
			return err
		}
		add(func() { try("iptables", append([]string{"-t", "mangle", "-D"}, mangle[2:]...)...) })

		// Source address was chosen while the default route pointed at the TUN,
		// so rewrite it to the physical NIC's address or replies never return.
		nat := []string{"POSTROUTING", "-o", dev, "-m", "mark", "--mark", cfg.DNSMark, "-j", "MASQUERADE"}
		if err := sh("iptables", append([]string{"-t", "nat", "-A"}, nat...)...); err != nil {
			return err
		}
		add(func() { try("iptables", append([]string{"-t", "nat", "-D"}, nat...)...) })

		// Loose reverse-path filtering so replies are accepted
		add(func() {
			if oldRPAll != "" {
				_ = sysctlSet(rpAllKey, oldRPAll)
			}
			if oldRPDev != "" {
				_ = sysctlSet(rpDevKey, oldRPDev)
			}
		})
		_ = sysctlSet(rpAllKey, "2")
		_ = sysctlSet(rpDevKey, "2")
	}

	// 7. Redirect everything else into the tunnel
	say("[*] Redirecting default route into %s...", cfg.TunDev)
	if err := sh("ip", "route", "add", "default", "dev", cfg.TunDev, "metric", "10"); err != nil {
		return err
	}
	add(func() { try("ip", "route", "del", "default", "dev", cfg.TunDev) })
	if cfg.DisableIPv6 {
		// Previous values are restored on disconnect.
		say("[*] Disabling IPv6...")
		for _, key := range []string{"net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"} {
			key, old := key, sysctlGet(key)
			if err := sysctlSet(key, "1"); err != nil {
				say("[!] %v", err)
				continue
			}
			if old != "" {
				add(func() { _ = sysctlSet(key, old) })
			}
		}
	} else if err := sh("ip", "-6", "route", "add", "default", "unreachable", "metric", "1"); err == nil {
		// IPv6 stays on but is blocked so it can't leak around the tunnel.
		add(func() { try("ip", "-6", "route", "del", "default", "unreachable", "metric", "1") })
	}

	say("==========================================================")
	if cfg.DNSBypass {
		say(" [SUCCESS] VPN connected (UDP/53 bypasses the tunnel)")
	} else {
		say(" [SUCCESS] VPN connected")
	}
	say(" Test TCP:  curl -4 https://ifconfig.me")
	say(" Test DNS:  dig +short example.com")
	say(" Press CTRL+C to stop.")
	say("==========================================================")

	select {
	case <-ctx.Done():
	case <-chisel.exited:
		say("[!] Chisel client exited: %v", chisel.err)
	case <-t2s.exited:
		say("[!] tun2socks exited: %v", t2s.err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// CLI + interactive menu
// ----------------------------------------------------------------------------

var stdin = bufio.NewReader(os.Stdin)

func prompt(msg string) string {
	fmt.Print(msg)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

func show(cfg Config) {
	fmt.Printf("Config file: %s\n\n", configPath())
	for _, e := range cfg.List() {
		fmt.Printf("  %-22s = %s\n", e.Key, e.Val)
	}
}

func editAll(cfg *Config) bool {
	fmt.Println("Press Enter to keep the current value.")
	changed := false
	for _, e := range cfg.List() {
		for {
			in := prompt(fmt.Sprintf("%s [%s]: ", e.Desc, e.Val))
			if in == "" {
				break
			}
			if err := cfg.trySet(e.Key, in); err != nil {
				fmt.Println("  invalid:", err)
				continue
			}
			changed = true
			break
		}
	}
	return changed
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func menu(cfg Config) {
	for {
		fmt.Print("\n== chiselvpn ==\n1) Connect\n2) Show settings\n3) Edit settings\n4) Reset to defaults\n0) Quit\n")
		switch prompt("> ") {
		case "1":
			if err := connect(cfg); err != nil {
				fmt.Println("error:", err)
			}
		case "2":
			show(cfg)
		case "3":
			if editAll(&cfg) {
				if err := SaveConfig(cfg); err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Println("Saved.")
				}
			}
		case "4":
			if strings.EqualFold(prompt("Reset all settings? (y/N): "), "y") {
				cfg = DefaultConfig()
				if err := SaveConfig(cfg); err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Println("Defaults restored.")
				}
			}
		case "0", "q":
			return
		}
	}
}

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		fatal(err)
	}
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "gui" {
		runGUI(cfg)
		return
	}
	switch args[0] {
	case "menu":
		menu(cfg)
	case "stop":
		if err := sendControl("stop"); err != nil {
			fatal(fmt.Errorf("no running session: %w", err))
		}
		fmt.Println("Stop requested.")
	case "up":
		fs := flag.NewFlagSet("up", flag.ExitOnError)
		cb := fs.String("chisel-bin", "", "override chisel binary path")
		tb := fs.String("tun2socks-bin", "", "override badvpn-tun2socks binary path")
		_ = fs.Parse(args[1:])
		if *cb != "" {
			cfg.ChiselBin = *cb
		}
		if *tb != "" {
			cfg.Tun2socksBin = *tb
		}
		if err := connect(cfg); err != nil {
			fatal(err)
		}
	case "show":
		show(cfg)
	case "path":
		fmt.Println(configPath())
	case "keys":
		for _, e := range cfg.List() {
			fmt.Printf("  %-22s %s\n", e.Key, e.Desc)
		}
	case "set":
		rest := args[1:]
		if len(rest) == 0 {
			fatal(errors.New("usage: chiselvpn set key value [key value ...]  (or key=value)"))
		}
		for i := 0; i < len(rest); i++ {
			k, v, ok := strings.Cut(rest[i], "=")
			if !ok {
				if i+1 >= len(rest) {
					fatal(fmt.Errorf("missing value for %s", k))
				}
				i++
				v = rest[i]
			}
			if err := cfg.trySet(k, v); err != nil {
				fatal(err)
			}
		}
		if err := SaveConfig(cfg); err != nil {
			fatal(err)
		}
		fmt.Println("Saved.")
	case "edit":
		if editAll(&cfg) {
			if err := SaveConfig(cfg); err != nil {
				fatal(err)
			}
			fmt.Println("Saved.")
		}
	case "reset":
		if err := SaveConfig(DefaultConfig()); err != nil {
			fatal(err)
		}
		fmt.Println("Defaults restored.")
	default:
		fmt.Fprintln(os.Stderr, "usage: chiselvpn [gui|menu|up|stop|show|set|edit|reset|keys|path]")
		os.Exit(2)
	}
}
