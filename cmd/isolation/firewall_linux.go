//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	fwBackupFile   = filepath.Join(backupDir, "fw_rules.backup")
	iptBackupFile  = filepath.Join(backupDir, "fw_rules.ipt")
	ip6BackupFile  = filepath.Join(backupDir, "fw_rules.ip6")
	backendFile    = filepath.Join(backupDir, "backend.type")
	isolatedMarker = filepath.Join(backupDir, ".isolated")
)

func runCmd(name string, args ...string) (string, string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return string(out), msg
	}
	return string(out), ""
}

func canRefresh() bool {
	return isIsolated()
}

func detectBackend() string {
	if _, err := exec.LookPath("nft"); err == nil {
		return "nftables"
	}
	return "iptables"
}

func isIsolated() bool {
	_, err := os.Stat(isolatedMarker)
	return err == nil
}

func dnsServers() []string {
	for _, path := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if ips := parseResolvConf(string(data)); len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func ipBin(ip string) string {
	if isIPv6(ip) {
		return "ip6tables"
	}
	return "iptables"
}

func nftFam(ip string) string {
	if isIPv6(ip) {
		return "ip6"
	}
	return "ip"
}

func setFor(ip string) string {
	if isIPv6(ip) {
		return "fqdn6"
	}
	return "fqdn4"
}

func isolate(ipException []string) (string, string) {
	staticIPs, names, resolved, err := expandExceptions(ipException)
	if err != nil {
		return "", err.Error()
	}
	os.MkdirAll(backupDir, 0755)
	if isIsolated() {
		return "", "The device is already isolated, no action was taken."
	}

	backend := detectBackend()
	dns := dnsServers()
	var s steps
	switch backend {
	case "nftables":
		isolateNftables(&s, staticIPs, resolved, dns)
	default:
		isolateIptables(&s, staticIPs, resolved, dns)
	}
	if len(s.failed) > 0 {
		return "", summaryLine(staticIPs, names, dns, "", s.failed)
	}
	os.WriteFile(backendFile, []byte(backend), 0644)
	os.WriteFile(isolatedMarker, []byte("1"), 0644)

	refresh := ""
	if len(names) > 0 {
		writeLines(fqdnNamesFile, names)
		writeLines(fqdnIPsFile, resolved)
		writeLines(staticIPsFile, staticIPs)
		_, errOut := installRefreshTask()
		s.note("refresh-task", errOut)
		refresh = "clr-fqdn"
	}
	if len(s.failed) > 0 {
		return "", summaryLine(staticIPs, names, dns, refresh, s.failed)
	}
	return summaryLine(staticIPs, names, dns, refresh, nil), ""
}

func sh(s *steps, name, script string) {
	_, errOut := runCmd("sh", "-c", script)
	s.note(name, errOut)
}

func isolateNftables(s *steps, staticIPs, resolved, dns []string) {
	sh(s, "backup", fmt.Sprintf("nft list ruleset > %s", fwBackupFile))
	runCmd("sh", "-c", fmt.Sprintf("iptables-save > %s", iptBackupFile))
	runCmd("sh", "-c", fmt.Sprintf("ip6tables-save > %s", ip6BackupFile))
	sh(s, "flush", "nft flush ruleset")
	sh(s, "table", "nft add table inet clr_isolate")
	sh(s, "input", `nft add chain inet clr_isolate input '{ type filter hook input priority 0; policy drop; }'`)
	sh(s, "output", `nft add chain inet clr_isolate output '{ type filter hook output priority 0; policy drop; }'`)
	sh(s, "forward", `nft add chain inet clr_isolate forward '{ type filter hook forward priority 0; policy drop; }'`)
	sh(s, "loopback-in", "nft add rule inet clr_isolate input iif lo accept")
	sh(s, "loopback-out", "nft add rule inet clr_isolate output oif lo accept")
	addNftDNS(s, dns)
	sh(s, "set4", `nft add set inet clr_isolate fqdn4 '{ type ipv4_addr; }'`)
	sh(s, "set6", `nft add set inet clr_isolate fqdn6 '{ type ipv6_addr; }'`)
	sh(s, "set4-in", "nft add rule inet clr_isolate input ip saddr @fqdn4 accept")
	sh(s, "set4-out", "nft add rule inet clr_isolate output ip daddr @fqdn4 accept")
	sh(s, "set6-in", "nft add rule inet clr_isolate input ip6 saddr @fqdn6 accept")
	sh(s, "set6-out", "nft add rule inet clr_isolate output ip6 daddr @fqdn6 accept")

	for _, ip := range staticIPs {
		fam := nftFam(ip)
		sh(s, "static-in", fmt.Sprintf("nft add rule inet clr_isolate input %s saddr %s accept", fam, ip))
		sh(s, "static-out", fmt.Sprintf("nft add rule inet clr_isolate output %s daddr %s accept", fam, ip))
	}
	for _, ip := range resolved {
		_, errOut := runCmd("sh", "-c", fmt.Sprintf("nft add element inet clr_isolate %s { %s }", setFor(ip), ip))
		s.note("fqdn", errOut)
	}
}

func addNftDNS(s *steps, dns []string) {
	for _, r := range dns {
		fam := nftFam(r)
		sh(s, "dns-out", fmt.Sprintf("nft add rule inet clr_isolate output %s daddr %s udp dport 53 accept", fam, r))
		sh(s, "dns-out", fmt.Sprintf("nft add rule inet clr_isolate output %s daddr %s tcp dport 53 accept", fam, r))
		sh(s, "dns-in", fmt.Sprintf("nft add rule inet clr_isolate input %s saddr %s udp sport 53 accept", fam, r))
		sh(s, "dns-in", fmt.Sprintf("nft add rule inet clr_isolate input %s saddr %s tcp sport 53 accept", fam, r))
	}
}

func isolateIptables(s *steps, staticIPs, resolved, dns []string) {
	sh(s, "backup", fmt.Sprintf("iptables-save > %s", fwBackupFile))
	sh(s, "flush", "iptables -F")
	sh(s, "policy-in", "iptables -P INPUT DROP")
	sh(s, "policy-out", "iptables -P OUTPUT DROP")
	sh(s, "policy-fwd", "iptables -P FORWARD DROP")
	sh(s, "loopback-in", "iptables -A INPUT -i lo -j ACCEPT")
	sh(s, "loopback-out", "iptables -A OUTPUT -o lo -j ACCEPT")
	addIptDNS(s, dns)
	if len(resolved) > 0 {
		sh(s, "fqdn-chain-in", "iptables -N CLR_FQDN_IN")
		sh(s, "fqdn-chain-out", "iptables -N CLR_FQDN_OUT")
		sh(s, "fqdn-jump-in", "iptables -A INPUT -j CLR_FQDN_IN")
		sh(s, "fqdn-jump-out", "iptables -A OUTPUT -j CLR_FQDN_OUT")
		for _, ip := range resolved {
			if !isIPv6(ip) {
				continue
			}
			sh(s, "fqdn6-chain-in", "ip6tables -N CLR_FQDN_IN")
			sh(s, "fqdn6-chain-out", "ip6tables -N CLR_FQDN_OUT")
			sh(s, "fqdn6-jump-in", "ip6tables -A INPUT -j CLR_FQDN_IN")
			sh(s, "fqdn6-jump-out", "ip6tables -A OUTPUT -j CLR_FQDN_OUT")
			break
		}
	}
	for _, ip := range staticIPs {
		bin := ipBin(ip)
		sh(s, "static-in", fmt.Sprintf("%s -A INPUT -s %s -j ACCEPT", bin, ip))
		sh(s, "static-out", fmt.Sprintf("%s -A OUTPUT -d %s -j ACCEPT", bin, ip))
	}
	for _, ip := range resolved {
		bin := ipBin(ip)
		sh(s, "fqdn-in", fmt.Sprintf("%s -A CLR_FQDN_IN -s %s -j ACCEPT", bin, ip))
		sh(s, "fqdn-out", fmt.Sprintf("%s -A CLR_FQDN_OUT -d %s -j ACCEPT", bin, ip))
	}
}

func addIptDNS(s *steps, dns []string) {
	for _, r := range dns {
		bin := ipBin(r)
		sh(s, "dns-out", fmt.Sprintf("%s -A OUTPUT -d %s -p udp --dport 53 -j ACCEPT", bin, r))
		sh(s, "dns-out", fmt.Sprintf("%s -A OUTPUT -d %s -p tcp --dport 53 -j ACCEPT", bin, r))
		sh(s, "dns-in", fmt.Sprintf("%s -A INPUT -s %s -p udp --sport 53 -j ACCEPT", bin, r))
		sh(s, "dns-in", fmt.Sprintf("%s -A INPUT -s %s -p tcp --sport 53 -j ACCEPT", bin, r))
	}
}

func installRefreshTask() (string, string) {
	line := fmt.Sprintf("* * * * * root \"%s\" refresh\n", selfExe())
	if err := os.WriteFile("/etc/cron.d/clr-fqdn", []byte(line), 0644); err != nil {
		return "", err.Error()
	}
	return "fqdn refresh scheduled", ""
}

func removeRefreshTask() {
	os.Remove("/etc/cron.d/clr-fqdn")
}

func applyFQDN(add, remove, all []string) error {
	if !isIsolated() {
		return errors.New("not isolated")
	}
	backend, _ := os.ReadFile(backendFile)
	if strings.TrimSpace(string(backend)) == "nftables" {
		return applyNft(add, remove, all)
	}
	return applyIpt(add, remove)
}

func nftHasSets() bool {
	out, errOut := runCmd("nft", "list", "set", "inet", "clr_isolate", "fqdn4")
	return errOut == "" && strings.Contains(out, "fqdn4")
}

func applyNft(add, remove, all []string) error {
	if !nftHasSets() {
		return migrateNft(all)
	}
	for _, ip := range add {
		if _, errOut := runCmd("sh", "-c", fmt.Sprintf("nft add element inet clr_isolate %s { %s }", setFor(ip), ip)); errOut != "" {
			return errors.New(errOut)
		}
	}
	for _, ip := range remove {
		runCmd("sh", "-c", fmt.Sprintf("nft delete element inet clr_isolate %s { %s }", setFor(ip), ip))
	}
	return nil
}

func migrateNft(all []string) error {
	for _, script := range []string{
		`nft add set inet clr_isolate fqdn4 '{ type ipv4_addr; }'`,
		`nft add set inet clr_isolate fqdn6 '{ type ipv6_addr; }'`,
		"nft add rule inet clr_isolate input ip saddr @fqdn4 accept",
		"nft add rule inet clr_isolate output ip daddr @fqdn4 accept",
		"nft add rule inet clr_isolate input ip6 saddr @fqdn6 accept",
		"nft add rule inet clr_isolate output ip6 daddr @fqdn6 accept",
	} {
		if _, errOut := runCmd("sh", "-c", script); errOut != "" {
			return errors.New(errOut)
		}
	}
	for _, ip := range all {
		if _, errOut := runCmd("sh", "-c", fmt.Sprintf("nft add element inet clr_isolate %s { %s }", setFor(ip), ip)); errOut != "" {
			return errors.New(errOut)
		}
	}
	runCmd("nft", "flush", "chain", "inet", "clr_isolate", "fqdn_in")
	runCmd("nft", "flush", "chain", "inet", "clr_isolate", "fqdn_out")
	return nil
}

func applyIpt(add, remove []string) error {
	for _, ip := range add {
		bin := ipBin(ip)
		if _, errOut := runCmd(bin, "-A", "CLR_FQDN_IN", "-s", ip, "-j", "ACCEPT"); errOut != "" {
			return errors.New(errOut)
		}
		if _, errOut := runCmd(bin, "-A", "CLR_FQDN_OUT", "-d", ip, "-j", "ACCEPT"); errOut != "" {
			return errors.New(errOut)
		}
	}
	for _, ip := range remove {
		bin := ipBin(ip)
		runCmd(bin, "-D", "CLR_FQDN_IN", "-s", ip, "-j", "ACCEPT")
		runCmd(bin, "-D", "CLR_FQDN_OUT", "-d", ip, "-j", "ACCEPT")
	}
	return nil
}

func restoreSaved(bin, path string) string {
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		return ""
	}
	_, errOut := runCmd("sh", "-c", fmt.Sprintf("%s-restore < %s", bin, path))
	return errOut
}

func release() (string, string) {
	if !isIsolated() {
		return "", "The host is not isolated, or the backup has been removed."
	}
	resume := pauseRefresh()
	defer resume()

	backend, _ := os.ReadFile(backendFile)
	var errOut string
	switch strings.TrimSpace(string(backend)) {
	case "nftables":
		_, errOut = runCmd("nft", "flush", "ruleset")
		if errOut == "" {
			_, errOut = runCmd("nft", "-f", fwBackupFile)
		}
		if errOut != "" {
			iptInfo, iptErr := os.Stat(iptBackupFile)
			ip6Info, ip6Err := os.Stat(ip6BackupFile)
			hasIpt := iptErr == nil && iptInfo.Size() > 0
			hasIP6 := ip6Err == nil && ip6Info.Size() > 0
			if hasIpt || hasIP6 {
				errOut = ""
				if hasIpt {
					errOut = restoreSaved("iptables", iptBackupFile)
				}
				if errOut == "" && hasIP6 {
					errOut = restoreSaved("ip6tables", ip6BackupFile)
				}
			}
		}
	default:
		saved, _ := os.ReadFile(fwBackupFile)
		_, errOut = runCmd("sh", "-c", fmt.Sprintf("iptables-restore < %s", fwBackupFile))
		if errOut == "" && !strings.Contains(string(saved), "*filter") {
			for _, script := range []string{
				"iptables -F",
				"iptables -X",
				"iptables -P INPUT ACCEPT",
				"iptables -P OUTPUT ACCEPT",
				"iptables -P FORWARD ACCEPT",
			} {
				if _, e := runCmd("sh", "-c", script); e != "" {
					errOut = e
					break
				}
			}
		}
	}
	if errOut != "" {
		return "", "restore failed; backup kept at " + fwBackupFile
	}
	os.Remove(fwBackupFile)
	os.Remove(iptBackupFile)
	os.Remove(ip6BackupFile)
	os.Remove(backendFile)
	os.Remove(isolatedMarker)
	os.Remove(fqdnNamesFile)
	os.Remove(fqdnIPsFile)
	os.Remove(staticIPsFile)
	removeRefreshTask()
	return "released", ""
}
