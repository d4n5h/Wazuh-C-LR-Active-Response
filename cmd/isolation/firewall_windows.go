//go:build windows

package main

import (
	"fmt"
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

func addAllow(name, dir, protocol, remoteip string) (string, string) {
	return runCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name, "dir="+dir, "action=allow", "protocol="+protocol,
		"remoteip="+remoteip, "profile=any", "enable=yes")
}

func addFQDNAllow(name string) (string, string) {
	script := fmt.Sprintf(`$id = '{' + [guid]::NewGuid().ToString() + '}'
New-NetFirewallDynamicKeywordAddress -Id $id -Keyword '%s' -AutoResolve $true
New-NetFirewallRule -DisplayName 'allow-siem-fqdn-out' -Direction Outbound -Action Allow -Profile Any -Enabled True -RemoteDynamicKeywordAddresses $id | Out-Null
New-NetFirewallRule -DisplayName 'allow-siem-fqdn-in' -Direction Inbound -Action Allow -Profile Any -Enabled True -RemoteDynamicKeywordAddresses $id | Out-Null
$id`, name)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		} else {
			stderr = err.Error()
		}
		return string(out), stderr
	}
	return strings.TrimSpace(string(out)), ""
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

	for _, ip := range staticIPs {
		for _, dir := range []string{"in", "out"} {
			name := "allow-siem-out"
			if dir == "in" {
				name = "allow-siem-in"
			}
			for _, proto := range []string{"tcp", "udp"} {
				stdout, stderr = addAllow(name, dir, proto, ip)
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
				stdout, stderr = addAllow(name, dir, proto, ip)
				outs = append(outs, stdout)
				errs = append(errs, stderr)
			}
		}
	}

	stdout, stderr = addAllow("allow-dns-out", "out", "any", "dns")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = addAllow("allow-dhcp-out", "out", "udp", "dhcp")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	var keywordIDs []string
	for _, name := range names {
		stdout, stderr = addFQDNAllow(name)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
		if strings.HasPrefix(stdout, "{") && strings.HasSuffix(stdout, "}") {
			keywordIDs = append(keywordIDs, stdout)
		}
	}
	if len(keywordIDs) > 0 {
		os.WriteFile(fqdnFile, []byte(strings.Join(keywordIDs, "\n")), 0644)
	}

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
				addAllow(name, dir, proto, ip)
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
