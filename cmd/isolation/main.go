package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

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

func resolveNames(names []string) ([]string, error) {
	_, _, resolved, err := expandExceptions(names)
	return resolved, err
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
	fqdnNamesFile = filepath.Join(backupDir, "fqdn.txt")
	fqdnIPsFile   = filepath.Join(backupDir, "fqdn-ips.txt")
	staticIPsFile = filepath.Join(backupDir, "static-ips.txt")
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			shared.Debug(debugFile, fmt.Sprintf("PANIC: %v", r))
		}
	}()

	if len(os.Args) > 1 && os.Args[1] == "refresh" {
		refresh()
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
