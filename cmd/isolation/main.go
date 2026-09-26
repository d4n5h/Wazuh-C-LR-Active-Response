package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

var (
	debugFile = filepath.Join(shared.WarDir, "isolation.log")
	backupDir = filepath.Join(shared.WarDir, "backup")
)

type OutputResult struct {
	Command    string            `json:"command"`
	Origin     map[string]string `json:"origin"`
	Parameters map[string]string `json:"parameters"`
	CLR        map[string]string `json:"clr"`
}

func output(program, action, user, stdout, stderr, logHeader string) {
	result := OutputResult{
		Command:    "add",
		Origin:     map[string]string{"name": "C-LR", "module": "Isolation"},
		Parameters: map[string]string{"program": program},
		CLR: map[string]string{
			"action": action,
			"user":   user,
			"result": fmt.Sprintf("stdout: %s\nstderr: %s", stdout, stderr),
		},
	}
	shared.WriteLog(logHeader, result)
}

func isValidIP(ip string) bool {
	if net.ParseIP(ip) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(ip)
	return err == nil
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

func isFQDN(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.Contains(name, ".") == false {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func expandExceptions(items []string) (staticIPs []string, names []string, resolved []string, err error) {
	seenStatic := map[string]struct{}{}
	seenResolved := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if isValidIP(item) {
			if _, ok := seenStatic[item]; !ok {
				seenStatic[item] = struct{}{}
				staticIPs = append(staticIPs, item)
			}
			continue
		}
		if !isFQDN(item) {
			return nil, nil, nil, fmt.Errorf("invalid exception %q: expected an IP, CIDR, or FQDN", item)
		}
		names = append(names, item)
		looked, lerr := net.LookupIP(item)
		if lerr != nil || len(looked) == 0 {
			return nil, nil, nil, fmt.Errorf("could not resolve %s", item)
		}
		for _, ip := range looked {
			s := ip.String()
			if v4 := ip.To4(); v4 != nil {
				s = v4.String()
			}
			if _, ok := seenResolved[s]; ok {
				continue
			}
			seenResolved[s] = struct{}{}
			resolved = append(resolved, s)
		}
	}
	return staticIPs, names, resolved, nil
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func writeLines(path string, lines []string) error {
	body := strings.Join(lines, "\n")
	if len(lines) > 0 {
		body += "\n"
	}
	return os.WriteFile(path, []byte(body), 0644)
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func resolveEach(names, prev []string, lookup func(string) ([]net.IP, error)) ([]string, bool) {
	var out []string
	complete := true
	for _, n := range names {
		ips, err := lookup(n)
		if err != nil || len(ips) == 0 {
			complete = false
			continue
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			out = append(out, ip.String())
		}
	}
	if !complete {
		out = append(out, prev...)
	}
	return unique(out), complete
}

func diff(old, next []string) (add, remove []string) {
	have := map[string]struct{}{}
	want := map[string]struct{}{}
	for _, s := range old {
		have[s] = struct{}{}
	}
	for _, s := range next {
		want[s] = struct{}{}
	}
	for _, s := range next {
		if _, ok := have[s]; !ok {
			add = append(add, s)
		}
	}
	for _, s := range old {
		if _, ok := want[s]; !ok {
			remove = append(remove, s)
		}
	}
	return add, remove
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, s := range a {
		count[s]++
	}
	for _, s := range b {
		if count[s] == 0 {
			return false
		}
		count[s]--
	}
	return true
}

func selfExe() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}

var (
	fqdnNamesFile   = filepath.Join(backupDir, "fqdn.txt")
	fqdnIPsFile     = filepath.Join(backupDir, "fqdn-ips.txt")
	staticIPsFile   = filepath.Join(backupDir, "static-ips.txt")
	refreshStopFile = filepath.Join(backupDir, "refresh.stop")
)

const (
	refreshEvery = 10 * time.Second
	refreshFor   = 55 * time.Second
)

type steps struct {
	failed []string
}

func (s *steps) note(name, errOut string) {
	msg := strings.Join(strings.Fields(errOut), " ")
	if msg != "" {
		s.failed = append(s.failed, name+": "+msg)
	}
}

func lookupIPs(name string) []string {
	ips, err := net.LookupIP(name)
	if err != nil {
		return nil
	}
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		out = append(out, ip.String())
	}
	return unique(out)
}

func importOK(out, errOut string) bool {
	return strings.TrimSpace(errOut) == "" && strings.Contains(out, "Ok.")
}

func summaryLine(static, names, dns []string, refresh string, errs []string) string {
	stat, fqdn, dnsPart := "none", "none", "none"
	if len(static) > 0 {
		stat = strings.Join(static, ",")
	}
	if len(names) > 0 {
		parts := make([]string, 0, len(names))
		for _, n := range names {
			ips := lookupIPs(n)
			if len(ips) == 0 {
				parts = append(parts, n+"=unresolved")
				continue
			}
			parts = append(parts, n+"="+strings.Join(ips, ","))
		}
		fqdn = strings.Join(parts, " ")
	}
	if len(dns) > 0 {
		dnsPart = strings.Join(dns, ",")
	}
	if refresh == "" {
		refresh = "none"
	}
	line := fmt.Sprintf("isolated; static: %s; fqdn: %s; dns: %s; refresh: %s", stat, fqdn, dnsPart, refresh)
	if len(errs) > 0 {
		line += "; errors: " + strings.Join(errs, "; ")
	}
	return line
}

func lock(path string, stale time.Duration) (func(), bool) {
	open := func() (*os.File, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	}
	f, err := open()
	if err != nil {
		info, statErr := os.Stat(path)
		if statErr != nil || time.Since(info.ModTime()) < stale {
			return nil, false
		}
		os.Remove(path)
		f, err = open()
		if err != nil {
			return nil, false
		}
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	return func() {
		f.Close()
		os.Remove(path)
	}, true
}

func refreshLoop() {
	if !canRefresh() {
		return
	}
	os.MkdirAll(backupDir, 0755)
	unlock, ok := lock(filepath.Join(backupDir, "refresh.lock"), 2*time.Minute)
	if !ok {
		return
	}
	defer unlock()
	start := time.Now()
	for {
		if _, err := os.Stat(refreshStopFile); err == nil {
			return
		}
		names := readLines(fqdnNamesFile)
		if len(names) == 0 {
			return
		}
		prev := readLines(fqdnIPsFile)
		next, _ := resolveEach(names, prev, net.LookupIP)
		if len(next) > 0 && !sameSet(next, prev) {
			add, remove := diff(prev, next)
			if applyFQDN(add, remove, next) == nil {
				writeLines(fqdnIPsFile, next)
			}
		}
		if time.Since(start)+refreshEvery >= refreshFor {
			return
		}
		time.Sleep(refreshEvery)
	}
}

func pauseRefresh() func() {
	os.MkdirAll(backupDir, 0755)
	os.WriteFile(refreshStopFile, []byte("1"), 0644)
	deadline := time.Now().Add(12 * time.Second)
	var unlock func()
	for {
		var ok bool
		unlock, ok = lock(filepath.Join(backupDir, "refresh.lock"), 2*time.Minute)
		if ok || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return func() {
		if unlock != nil {
			unlock()
		}
		os.Remove(refreshStopFile)
	}
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			shared.Debug(debugFile, fmt.Sprintf("PANIC: %v", r))
		}
	}()

	if len(os.Args) > 1 && os.Args[1] == "refresh" {
		refreshLoop()
		return
	}

	input, raw, err := shared.ReadInput()
	dt := shared.CurrentDatetime()

	if err != nil {
		shared.Debug(debugFile, fmt.Sprintf("ReadInput error: %v (raw: %s)", err, raw))
		output("C-LR Isolation", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Isolation")
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	ipException := input.Parameters.ExtraArgs
	action := input.Parameters.Alert.Data.Action
	user := input.Parameters.Alert.Data.User
	debugMode := input.Parameters.Alert.Data.Debug

	if debugMode {
		shared.Debug(debugFile, "main: "+raw)
	}

	if user == "" {
		output(program, action, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}

	switch action {
	case "isolate":
		stdout, stderr := isolate(ipException)
		stdout = strings.ReplaceAll(stdout, "\n", " ")
		stderr = strings.ReplaceAll(stderr, "\n", " ")
		output(program, action, user, stdout, stderr, logHeader)
	case "release":
		stdout, stderr := release()
		stdout = strings.ReplaceAll(stdout, "\n", " ")
		stderr = strings.ReplaceAll(stderr, "\n", " ")
		output(program, action, user, stdout, stderr, logHeader)
	default:
		output(program, action, user, "", "No action was provided. Please specify an action in the alert [isolate, release] > data.", logHeader)
	}
}
