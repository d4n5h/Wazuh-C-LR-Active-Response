//go:build windows

package main

import (
	"errors"
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

func canRefresh() bool {
	_, err := os.Stat(fwRulesFile)
	return err == nil
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

func addAllow(s *steps, name, dir, protocol, remoteip, remoteport string) {
	args := []string{"netsh", "advfirewall", "firewall", "add", "rule",
		"name=" + name, "dir=" + dir, "action=allow", "protocol=" + protocol,
		"remoteip=" + remoteip, "profile=any", "enable=yes"}
	if remoteport != "" {
		args = append(args, "remoteport="+remoteport)
	}
	_, errOut := runCmd(args...)
	s.note(name, errOut)
}

func addGroup(s *steps, name, dir string, ips []string) {
	if len(ips) == 0 {
		return
	}
	addAllow(s, name, dir, "any", strings.Join(ips, ","), "")
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

	var s steps
	_, errOut := runCmd("netsh", "advfirewall", "export", fwRulesFile)
	s.note("export", errOut)
	_, errOut = runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=all")
	s.note("delete-rules", errOut)
	_, errOut = runCmd("netsh", "advfirewall", "firewall", "set", "rule", "name=all", "new", "enable=no")
	s.note("disable-rules", errOut)
	_, errOut = runCmd("netsh", "advfirewall", "set", "allprofiles", "state", "on")
	s.note("firewall-on", errOut)
	_, errOut = runCmd("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
	s.note("policy", errOut)
	_, errOut = runCmd("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block")
	s.note("profile", errOut)

	policy, _ := runCmd("netsh", "advfirewall", "show", "allprofiles")
	if strings.Contains(policy, "AllowOutbound") || strings.Count(policy, "BlockOutbound") < 3 {
		return "", "outbound policy is not block"
	}

	addGroup(&s, "allow-siem-in", "in", staticIPs)
	addGroup(&s, "allow-siem-out", "out", staticIPs)
	addGroup(&s, "allow-fqdn-in", "in", resolved)
	addGroup(&s, "allow-fqdn-out", "out", resolved)

	dns := dnsServers()
	if len(dns) > 0 {
		list := strings.Join(dns, ",")
		addAllow(&s, "allow-dns-out", "out", "udp", list, "53")
		addAllow(&s, "allow-dns-out", "out", "tcp", list, "53")
	}
	addAllow(&s, "allow-dhcp-out", "out", "udp", "dhcp", "67")

	refresh := ""
	if len(names) > 0 {
		writeLines(fqdnNamesFile, names)
		writeLines(fqdnIPsFile, resolved)
		writeLines(staticIPsFile, staticIPs)
		_, errOut = installRefreshTask()
		s.note("refresh-task", errOut)
		refresh = "C-LR-FQDN"
	}
	return summaryLine(staticIPs, names, dns, refresh, s.failed), ""
}

func installRefreshTask() (string, string) {
	tr := `"` + selfExe() + `" refresh`
	return runCmd("schtasks", "/create", "/f", "/sc", "minute", "/mo", "1", "/tn", "C-LR-FQDN", "/ru", "SYSTEM", "/rl", "HIGHEST", "/tr", tr)
}

func removeRefreshTask() {
	runCmd("schtasks", "/delete", "/tn", "C-LR-FQDN", "/f")
}

func applyFQDN(_, _, all []string) error {
	if len(all) == 0 {
		return errors.New("no addresses")
	}
	list := strings.Join(all, ",")
	for _, name := range []string{"allow-fqdn-in", "allow-fqdn-out"} {
		_, errOut := runCmd("netsh", "advfirewall", "firewall", "set", "rule",
			"name="+name, "new", "remoteip="+list)
		if strings.TrimSpace(errOut) != "" {
			return errors.New(strings.TrimSpace(errOut))
		}
	}
	return nil
}

func release() (string, string) {
	if _, err := os.Stat(fwRulesFile); err != nil {
		return "", "The host is not isolated, or the backup has been removed."
	}
	resume := pauseRefresh()
	defer resume()
	out, errOut := runCmd("netsh", "advfirewall", "import", fwRulesFile)
	if !importOK(out, errOut) {
		return "", "restore failed; backup kept at " + fwRulesFile
	}
	removeRefreshTask()
	removeFQDNKeywords()
	for _, f := range []string{fwRulesFile, fqdnNamesFile, fqdnIPsFile, staticIPsFile} {
		os.Remove(f)
	}
	return "released", ""
}
