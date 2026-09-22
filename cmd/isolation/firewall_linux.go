//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	fwBackupFile  = filepath.Join(backupDir, "fw_rules.backup")
	backendFile   = filepath.Join(backupDir, "backend.type")
	isolatedMarker = filepath.Join(backupDir, ".isolated")
)

func runCmd(name string, args ...string) (string, string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err.Error()
	}
	return string(out), ""
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
	var outs, errs []string

	switch backend {
	case "nftables":
		stdout, stderr := isolateNftables(staticIPs, resolved, len(names) > 0)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	default:
		stdout, stderr := isolateIptables(staticIPs, resolved, len(names) > 0)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	for _, e := range errs {
		if e != "" {
			return strings.Join(outs, " "), strings.Join(errs, " ")
		}
	}
	os.WriteFile(backendFile, []byte(backend), 0644)
	os.WriteFile(isolatedMarker, []byte("1"), 0644)

	if len(names) > 0 {
		writeLines(fqdnNamesFile, names)
		writeLines(fqdnIPsFile, resolved)
		writeLines(staticIPsFile, staticIPs)
		stdout, stderr := installRefreshTask()
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	return strings.Join(outs, " "), strings.Join(errs, " ")
}

func addNftIP(chain, fam, field, ip string) (string, string) {
	return runCmd("nft", "add", "rule", "inet", "clr_isolate", chain, fam, field, ip, "accept")
}

func isolateNftables(staticIPs, resolved []string, allowDNS bool) (string, string) {
	var outs, errs []string

	stdout, stderr := runCmd("sh", "-c", fmt.Sprintf("nft list ruleset > %s", fwBackupFile))
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("nft", "flush", "ruleset")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("nft", "add", "table", "inet", "clr_isolate")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("sh", "-c", `nft add chain inet clr_isolate input '{ type filter hook input priority 0; policy drop; }'`)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("sh", "-c", `nft add chain inet clr_isolate output '{ type filter hook output priority 0; policy drop; }'`)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	if allowDNS {
		for _, rule := range []string{
			"nft add rule inet clr_isolate output udp dport 53 accept",
			"nft add rule inet clr_isolate output tcp dport 53 accept",
			"nft add rule inet clr_isolate input udp sport 53 accept",
			"nft add rule inet clr_isolate input tcp sport 53 accept",
			"nft add chain inet clr_isolate fqdn_in",
			"nft add chain inet clr_isolate fqdn_out",
			"nft add rule inet clr_isolate input jump fqdn_in",
			"nft add rule inet clr_isolate output jump fqdn_out",
		} {
			stdout, stderr = runCmd("sh", "-c", rule)
			outs = append(outs, stdout)
			errs = append(errs, stderr)
		}
	}

	for _, ip := range staticIPs {
		fam := "ip"
		if isIPv6(ip) {
			fam = "ip6"
		}
		stdout, stderr = addNftIP("input", fam, "saddr", ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
		stdout, stderr = addNftIP("output", fam, "daddr", ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	for _, ip := range resolved {
		fam := "ip"
		if isIPv6(ip) {
			fam = "ip6"
		}
		stdout, stderr = addNftIP("fqdn_in", fam, "saddr", ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
		stdout, stderr = addNftIP("fqdn_out", fam, "daddr", ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	return strings.Join(outs, " "), strings.Join(errs, " ")
}

func addIptablesIP(bin, chain, flag, ip string) (string, string) {
	return runCmd(bin, "-A", chain, flag, ip, "-j", "ACCEPT")
}

func isolateIptables(staticIPs, resolved []string, allowDNS bool) (string, string) {
	var outs, errs []string

	stdout, stderr := runCmd("sh", "-c", fmt.Sprintf("iptables-save > %s", fwBackupFile))
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("iptables", "-F")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("iptables", "-P", "INPUT", "DROP")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("iptables", "-P", "OUTPUT", "DROP")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("iptables", "-P", "FORWARD", "DROP")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	if allowDNS {
		for _, spec := range [][]string{
			{"OUTPUT", "-p", "udp", "--dport", "53"},
			{"OUTPUT", "-p", "tcp", "--dport", "53"},
			{"INPUT", "-p", "udp", "--sport", "53"},
			{"INPUT", "-p", "tcp", "--sport", "53"},
		} {
			args := append([]string{"iptables", "-A"}, spec...)
			args = append(args, "-j", "ACCEPT")
			stdout, stderr = runCmd(args[0], args[1:]...)
			outs = append(outs, stdout)
			errs = append(errs, stderr)
		}
		stdout, stderr = runCmd("iptables", "-N", "CLR_FQDN_IN")
		outs = append(outs, stdout)
		errs = append(errs, stderr)
		stdout, stderr = runCmd("iptables", "-N", "CLR_FQDN_OUT")
		outs = append(outs, stdout)
		errs = append(errs, stderr)
		stdout, stderr = runCmd("iptables", "-A", "INPUT", "-j", "CLR_FQDN_IN")
		outs = append(outs, stdout)
		errs = append(errs, stderr)
		stdout, stderr = runCmd("iptables", "-A", "OUTPUT", "-j", "CLR_FQDN_OUT")
		outs = append(outs, stdout)
		errs = append(errs, stderr)
		for _, ip := range resolved {
			if isIPv6(ip) {
				runCmd("ip6tables", "-N", "CLR_FQDN_IN")
				runCmd("ip6tables", "-N", "CLR_FQDN_OUT")
				runCmd("ip6tables", "-A", "INPUT", "-j", "CLR_FQDN_IN")
				runCmd("ip6tables", "-A", "OUTPUT", "-j", "CLR_FQDN_OUT")
				break
			}
		}
	}

	for _, ip := range staticIPs {
		bin := "iptables"
		if isIPv6(ip) {
			bin = "ip6tables"
		}
		stdout, stderr = addIptablesIP(bin, "INPUT", "-s", ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
		stdout, stderr = addIptablesIP(bin, "OUTPUT", "-d", ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	for _, ip := range resolved {
		bin := "iptables"
		inChain, outChain := "CLR_FQDN_IN", "CLR_FQDN_OUT"
		if isIPv6(ip) {
			bin = "ip6tables"
		}
		stdout, stderr = addIptablesIP(bin, inChain, "-s", ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
		stdout, stderr = addIptablesIP(bin, outChain, "-d", ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	return strings.Join(outs, " "), strings.Join(errs, " ")
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

func refresh() {
	if !isIsolated() {
		return
	}
	names := readLines(fqdnNamesFile)
	if len(names) == 0 {
		return
	}
	resolved, err := resolveNames(names)
	if err != nil || len(resolved) == 0 || sameSet(resolved, readLines(fqdnIPsFile)) {
		return
	}
	backend, _ := os.ReadFile(backendFile)
	if strings.TrimSpace(string(backend)) == "nftables" {
		runCmd("nft", "flush", "chain", "inet", "clr_isolate", "fqdn_in")
		runCmd("nft", "flush", "chain", "inet", "clr_isolate", "fqdn_out")
		for _, ip := range resolved {
			fam := "ip"
			if isIPv6(ip) {
				fam = "ip6"
			}
			addNftIP("fqdn_in", fam, "saddr", ip)
			addNftIP("fqdn_out", fam, "daddr", ip)
		}
	} else {
		runCmd("iptables", "-F", "CLR_FQDN_IN")
		runCmd("iptables", "-F", "CLR_FQDN_OUT")
		runCmd("ip6tables", "-F", "CLR_FQDN_IN")
		runCmd("ip6tables", "-F", "CLR_FQDN_OUT")
		for _, ip := range resolved {
			bin := "iptables"
			if isIPv6(ip) {
				bin = "ip6tables"
			}
			addIptablesIP(bin, "CLR_FQDN_IN", "-s", ip)
			addIptablesIP(bin, "CLR_FQDN_OUT", "-d", ip)
		}
	}
	writeLines(fqdnIPsFile, resolved)
}

func release() (string, string) {
	if !isIsolated() {
		return "", "The host is not isolated, or the backup has been removed."
	}

	backend, _ := os.ReadFile(backendFile)
	var outs, errs []string
	var stdout, stderr string

	switch strings.TrimSpace(string(backend)) {
	case "nftables":
		stdout, stderr = runCmd("nft", "flush", "ruleset")
		outs = append(outs, stdout)
		errs = append(errs, stderr)

		stdout, stderr = runCmd("nft", "-f", fwBackupFile)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	default:
		stdout, stderr = runCmd("sh", "-c", fmt.Sprintf("iptables-restore < %s", fwBackupFile))
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	os.Remove(fwBackupFile)
	os.Remove(backendFile)
	os.Remove(isolatedMarker)
	os.Remove(fqdnNamesFile)
	os.Remove(fqdnIPsFile)
	os.Remove(staticIPsFile)
	removeRefreshTask()

	return strings.Join(outs, " "), strings.Join(errs, " ")
}
