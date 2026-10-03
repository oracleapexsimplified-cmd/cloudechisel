package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Get returns the raw (unmasked) value of a setting as a string.
func (c Config) Get(key string) string {
	rv := reflect.ValueOf(c)
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Tag.Get("json") == key {
			return fmt.Sprint(rv.Field(i).Interface())
		}
	}
	return ""
}

var settingGroups = []struct {
	title string
	keys  []string
}{
	{"Server", []string{"chisel_domain", "chisel_port", "chisel_auth"}},
	{"Local proxy / UDPGW", []string{"socks_port", "udpgw_port", "udpgw_max_connections", "udpgw_buffer_size"}},
	{"TUN interface", []string{"tun_dev", "tun_ip", "tun_netif_ip", "tun_prefix", "mtu", "disable_ipv6"}},
	{"DNS bypass", []string{"dns_bypass", "dns_mark", "dns_table", "dns_rule_prio"}},
	{"Advanced", []string{"log_level", "chisel_bin", "tun2socks_bin"}},
}

type gui struct {
	app fyne.App
	win fyne.Window
	cfg Config

	getters map[string]func() string
	setters map[string]func(string)

	status    *widget.Label
	server    *widget.Label
	btn       *widget.Button
	logLabel  *widget.Label
	logScroll *container.Scroll

	mu    sync.Mutex
	state string // idle | connecting | connected | stopping
	lines []string
	done  chan struct{}
}

func runGUI(cfg Config) {
	a := app.NewWithID("io.github.chiselvpn")
	g := &gui{
		app:     a,
		cfg:     cfg,
		state:   "idle",
		getters: map[string]func() string{},
		setters: map[string]func(string){},
	}
	g.win = a.NewWindow("Chisel VPN")
	g.win.Resize(fyne.NewSize(560, 680))
	g.win.SetContent(container.NewAppTabs(
		container.NewTabItemWithIcon("Connection", theme.ComputerIcon(), g.connectionTab()),
		container.NewTabItemWithIcon("Settings", theme.SettingsIcon(), g.settingsTab()),
	))
	g.win.SetCloseIntercept(g.onClose)
	g.win.ShowAndRun()
}

// ---------------------------------------------------------------- UI building

func (g *gui) connectionTab() fyne.CanvasObject {
	g.status = widget.NewLabel("")
	g.status.TextStyle = fyne.TextStyle{Bold: true}
	g.server = widget.NewLabel("")
	g.btn = widget.NewButton("Connect", g.toggle)
	g.btn.Importance = widget.HighImportance

	g.logLabel = widget.NewLabel("")
	g.logLabel.TextStyle = fyne.TextStyle{Monospace: true}
	g.logLabel.Wrapping = fyne.TextWrapOff
	g.logScroll = container.NewScroll(g.logLabel)

	g.updateServerLabel()
	g.render("idle")

	top := container.NewVBox(g.status, g.server, g.btn, widget.NewSeparator(), widget.NewLabel("Log"))
	return container.NewBorder(top, nil, nil, nil, g.logScroll)
}

func (g *gui) buildField(key, val string) (fyne.CanvasObject, func() string, func(string)) {
	switch key {
	case "dns_bypass", "disable_ipv6":
		label := map[string]string{
			"dns_bypass":   "Send UDP/53 out the physical NIC",
			"disable_ipv6": "Disable IPv6 while connected",
		}[key]
		ch := widget.NewCheck(label, nil)
		ch.SetChecked(val == "true")
		return ch,
			func() string { return strconv.FormatBool(ch.Checked) },
			func(s string) { ch.SetChecked(s == "true") }
	case "log_level":
		sel := widget.NewSelect([]string{"none", "error", "warning", "notice", "info", "debug"}, nil)
		sel.SetSelected(val)
		return sel, func() string { return sel.Selected }, func(s string) { sel.SetSelected(s) }
	case "chisel_auth":
		e := widget.NewPasswordEntry()
		e.SetPlaceHolder("user:pass (optional)")
		e.SetText(val)
		return e, func() string { return e.Text }, func(s string) { e.SetText(s) }
	default:
		e := widget.NewEntry()
		e.SetText(val)
		return e, func() string { return e.Text }, func(s string) { e.SetText(s) }
	}
}

func (g *gui) settingsTab() fyne.CanvasObject {
	desc := map[string]string{}
	for _, e := range g.cfg.List() {
		desc[e.Key] = e.Desc
	}

	acc := widget.NewAccordion()
	acc.MultiOpen = true
	for _, grp := range settingGroups {
		form := widget.NewForm()
		for _, k := range grp.keys {
			obj, get, set := g.buildField(k, g.cfg.Get(k))
			g.getters[k], g.setters[k] = get, set
			form.AppendItem(widget.NewFormItem(desc[k], obj))
		}
		acc.Append(widget.NewAccordionItem(grp.title, form))
	}
	acc.OpenAll()

	save := widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), g.saveSettings)
	save.Importance = widget.HighImportance
	reset := widget.NewButtonWithIcon("Reset to defaults", theme.ViewRefreshIcon(), g.resetSettings)
	note := widget.NewLabel("Changes apply the next time you connect.")

	bottom := container.NewVBox(widget.NewSeparator(), note, container.NewHBox(layout.NewSpacer(), reset, save))
	return container.NewBorder(nil, bottom, nil, nil, container.NewVScroll(acc))
}

// ------------------------------------------------------------------ settings

// collect reads every widget into a new, validated Config.
func (g *gui) collect() (Config, error) {
	n := g.cfg
	for _, e := range g.cfg.List() {
		get, ok := g.getters[e.Key]
		if !ok {
			continue
		}
		if err := n.trySet(e.Key, get()); err != nil {
			return g.cfg, fmt.Errorf("%s: %w", e.Desc, err)
		}
	}
	return n, nil
}

func (g *gui) saveSettings() {
	cfg, err := g.collect()
	if err != nil {
		dialog.ShowError(err, g.win)
		return
	}
	if err := SaveConfig(cfg); err != nil {
		dialog.ShowError(err, g.win)
		return
	}
	g.cfg = cfg
	g.updateServerLabel()
	dialog.ShowInformation("Saved", "Settings saved.\nThey apply the next time you connect.", g.win)
}

func (g *gui) resetSettings() {
	dialog.ShowConfirm("Reset settings", "Restore all settings to their defaults?", func(ok bool) {
		if !ok {
			return
		}
		def := DefaultConfig()
		for k, set := range g.setters {
			set(def.Get(k))
		}
		if err := SaveConfig(def); err != nil {
			dialog.ShowError(err, g.win)
			return
		}
		g.cfg = def
		g.updateServerLabel()
	}, g.win)
}

func (g *gui) updateServerLabel() {
	g.server.SetText(fmt.Sprintf("Server: %s:%d", g.cfg.ChiselDomain, g.cfg.ChiselPort))
}

// ----------------------------------------------------------------- state / log

func (g *gui) render(state string) {
	fyne.Do(func() {
		switch state {
		case "idle":
			g.status.SetText("● Disconnected")
			g.btn.SetText("Connect")
			g.btn.Enable()
		case "connecting":
			g.status.SetText("● Connecting…")
			g.btn.SetText("Cancel")
			g.btn.Enable()
		case "connected":
			g.status.SetText("● Connected")
			g.btn.SetText("Disconnect")
			g.btn.Enable()
		case "stopping":
			g.status.SetText("● Disconnecting…")
			g.btn.Disable()
		}
	})
}

func (g *gui) setState(s string) {
	g.mu.Lock()
	g.state = s
	g.mu.Unlock()
	g.render(s)
}

func (g *gui) currentState() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

func (g *gui) appendLog(line string) {
	g.mu.Lock()
	g.lines = append(g.lines, line)
	if len(g.lines) > 500 {
		g.lines = g.lines[len(g.lines)-500:]
	}
	text := strings.Join(g.lines, "\n")
	g.mu.Unlock()
	fyne.Do(func() {
		g.logLabel.SetText(text)
		g.logScroll.ScrollToBottom()
	})
}

// -------------------------------------------------------------- connect / stop

func (g *gui) toggle() {
	switch g.currentState() {
	case "idle":
		g.connect()
	case "connecting", "connected":
		g.stop()
	}
}

func absLookPath(name string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%q not found in PATH (set its full path under Settings > Advanced)", name)
	}
	return filepath.Abs(p)
}

func (g *gui) connect() {
	cfg, err := g.collect()
	if err != nil {
		dialog.ShowError(err, g.win)
		return
	}
	if err := SaveConfig(cfg); err != nil {
		dialog.ShowError(err, g.win)
		return
	}
	g.cfg = cfg
	g.updateServerLabel()

	// pkexec strips PATH, so resolve the binaries here as the normal user.
	chiselPath, err := absLookPath(cfg.ChiselBin)
	if err == nil {
		var t2sPath string
		if t2sPath, err = absLookPath(cfg.Tun2socksBin); err == nil {
			g.start(cfg, chiselPath, t2sPath)
			return
		}
	}
	dialog.ShowError(err, g.win)
}

func (g *gui) start(cfg Config, chiselPath, t2sPath string) {
	pk, err := exec.LookPath("pkexec")
	if err != nil {
		dialog.ShowError(fmt.Errorf("pkexec (polkit) is required to get root rights; install it with your package manager"), g.win)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		dialog.ShowError(err, g.win)
		return
	}

	cmd := exec.Command(pk, exe, "up", "--chisel-bin="+chiselPath, "--tun2socks-bin="+t2sPath)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		dialog.ShowError(err, g.win)
		return
	}

	done := make(chan struct{})
	g.mu.Lock()
	g.lines = nil
	g.done = done
	g.mu.Unlock()
	g.setState("connecting")
	g.appendLog("[*] Waiting for authorization...")

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			g.appendLog(line)
			if strings.Contains(line, "[SUCCESS]") {
				g.mu.Lock()
				ok := g.state == "connecting"
				if ok {
					g.state = "connected"
				}
				g.mu.Unlock()
				if ok {
					g.render("connected")
				}
			}
		}
	}()

	go func() {
		werr := cmd.Wait()
		_ = pw.Close()
		<-scanDone
		g.mu.Lock()
		wasStopping := g.state == "stopping"
		g.state = "idle"
		close(done)
		g.mu.Unlock()
		if werr != nil && !wasStopping {
			g.appendLog(fmt.Sprintf("[!] Session ended: %v", werr))
		}
		g.render("idle")
	}()
}

func (g *gui) stop() {
	g.setState("stopping")
	go func() {
		// The control socket appears shortly after authorization; retry briefly
		// so "Cancel" works while the helper is still starting.
		var err error
		for i := 0; i < 20; i++ {
			if err = sendControl("stop"); err == nil {
				return
			}
			if g.currentState() == "idle" {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		g.appendLog(fmt.Sprintf("[!] Could not stop the session: %v", err))
		g.mu.Lock()
		if g.state == "stopping" {
			g.state = "connected"
		}
		g.mu.Unlock()
		g.render("connected")
	}()
}

func (g *gui) onClose() {
	if g.currentState() == "idle" {
		g.app.Quit()
		return
	}
	dialog.ShowConfirm("Quit", "The VPN is active. Disconnect and quit?", func(ok bool) {
		if !ok {
			return
		}
		g.mu.Lock()
		done := g.done
		g.mu.Unlock()
		g.stop()
		go func() {
			select {
			case <-done:
			case <-time.After(15 * time.Second):
			}
			fyne.Do(g.app.Quit)
		}()
	}, g.win)
}
