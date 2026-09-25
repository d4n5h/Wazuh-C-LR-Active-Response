//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	fwRulesFile = filepath.Join(backupDir, "fw_rules.xml")
	fqdnFile    = filepath.Join(backupDir, "fqdn-keywords.txt")
)

func runCmd(args ...string) (string, string) {
	cmd := exec.Command("cmd", append([]string{"/c"}, args...)...)
	out, err := cmd.Output()
	stderr := ""
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		} else {
			stderr = err.Error()
		}
	}
	return string(out), stderr
}

func addAllow(name, dir, protocol, remoteip, remoteport string) (string, string) {
	args := []string{"netsh", "advfirewall", "firewall", "add", "rule",
		"name=" + name, "dir=" + dir, "action=allow", "protocol=" + protocol,
		"remoteip=" + remoteip, "profile=any", "enable=yes"}
	if remoteport != "" {
		args = append(args, "remoteport="+remoteport)
	}
	return runCmd(args...)
}

func dnsServers() []string {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-DnsClientServerAddress | ForEach-Object { $_.ServerAddresses }`)
	out, _ := cmd.Output()
	seen := map[string]struct{}{}
	var ips []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !isValidIP(line) {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		ips = append(ips, line)
	}
	return ips
}

func removeFQDNKeywords() {
	data, err := os.ReadFile(fqdnFile)
	if err != nil {
		return
	}
	for _, id := range strings.Fields(string(data)) {
		exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Remove-NetFirewallDynamicKeywordAddress -Id '"+id+"'").Run()
	}
	os.Remove(fqdnFile)
}

func isolate(ipException []string) (string, string) {
	staticIPs, names, resolved, err := expandExceptions(ipException)
	if err != nil {
		return "", err.Error()
	}

	os.MkdirAll(backupDir, 0755)

	if _, err := os.Stat(fwRulesFile); err == nil {
		return "", "The device is already isolated, no action was taken."
	}

	var outs, errs []string

	stdout, stderr := runCmd("netsh", "advfirewall", "export", fwRulesFile)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=all")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("netsh", "advfirewall", "firewall", "set", "rule", "name=all", "new", "enable=no")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("netsh", "advfirewall", "set", "allprofiles", "state", "on")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	policy, _ := runCmd("netsh", "advfirewall", "show", "allprofiles")
	if strings.Contains(policy, "AllowOutbound") || strings.Count(policy, "BlockOutbound") < 3 {
		return strings.Join(outs, " "), "outbound policy is not block"
	}

	for _, ip := range staticIPs {
		for _, dir := range []string{"in", "out"} {
			name := "allow-siem-out"
			if dir == "in" {
				name = "allow-siem-in"
			}
			for _, proto := range []string{"tcp", "udp"} {
				stdout, stderr = addAllow(name, dir, proto, ip, "")
				outs = append(outs, stdout)
				errs = append(errs, stderr)
			}
		}
	}

	for _, ip := range resolved {
		for _, dir := range []string{"in", "out"} {
			name := "allow-fqdn-out"
			if dir == "in" {
				name = "allow-fqdn-in"
			}
			for _, proto := range []string{"tcp", "udp"} {
				stdout, stderr = addAllow(name, dir, proto, ip, "")
				outs = append(outs, stdout)
				errs = append(errs, stderr)
			}
		}
	}

	for _, ip := range dnsServers() {
		for _, proto := range []string{"udp", "tcp"} {
			stdout, stderr = addAllow("allow-dns-out", "out", proto, ip, "53")
			outs = append(outs, stdout)
			errs = append(errs, stderr)
		}
	}

	stdout, stderr = addAllow("allow-dhcp-out", "out", "udp", "dhcp", "67")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	if len(names) > 0 {
		writeLines(fqdnNamesFile, names)
		writeLines(fqdnIPsFile, resolved)
		writeLines(staticIPsFile, staticIPs)
		stdout, stderr = installRefreshTask()
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	return strings.Join(outs, " "), strings.Join(errs, " ")
}

func installRefreshTask() (string, string) {
	tr := `"` + selfExe() + `" refresh`
	return runCmd("schtasks", "/create", "/f", "/sc", "minute", "/mo", "1", "/tn", "C-LR-FQDN", "/ru", "SYSTEM", "/rl", "HIGHEST", "/tr", tr)
}

func removeRefreshTask() {
	runCmd("schtasks", "/delete", "/tn", "C-LR-FQDN", "/f")
}

func applyFQDNRules(ips []string) {
	runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=allow-fqdn-in")
	runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=allow-fqdn-out")
	for _, ip := range ips {
		for _, dir := range []string{"in", "out"} {
			name := "allow-fqdn-out"
			if dir == "in" {
				name = "allow-fqdn-in"
			}
			for _, proto := range []string{"tcp", "udp"} {
				addAllow(name, dir, proto, ip, "")
			}
		}
	}
}

func refresh() {
	names := readLines(fqdnNamesFile)
	if len(names) == 0 {
		return
	}
	resolved, err := resolveNames(names)
	if err != nil || len(resolved) == 0 || sameSet(resolved, readLines(fqdnIPsFile)) {
		return
	}
	applyFQDNRules(resolved)
	writeLines(fqdnIPsFile, resolved)
}

func release() (string, string) {
	if _, err := os.Stat(fwRulesFile); err == nil {
		stdout, stderr := runCmd("netsh", "advfirewall", "import", fwRulesFile)
		removeRefreshTask()
		removeFQDNKeywords()
		os.Remove(fwRulesFile)
		os.Remove(fqdnNamesFile)
		os.Remove(fqdnIPsFile)
		os.Remove(staticIPsFile)
		return stdout, stderr
	}
	return "", "The host is not isolated, or the backup has been removed."
}
