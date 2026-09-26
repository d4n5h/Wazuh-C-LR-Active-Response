//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const pfConf = "/etc/pf.conf"

var (
	fwBackupFile   = filepath.Join(backupDir, "pf.conf.backup")
	isolatedMarker = filepath.Join(backupDir, ".isolated")
	plistPath      = "/Library/LaunchDaemons/com.clr.fqdn.plist"
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

func isIsolated() bool {
	_, err := os.Stat(isolatedMarker)
	return err == nil
}

func dnsServers() []string {
	out, _ := runCmd("scutil", "--dns")
	if ips := parseScutilDNS(out); len(ips) > 0 {
		return ips
	}
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvConf(string(data))
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

	var s steps
	_, errOut := runCmd("cp", pfConf, fwBackupFile)
	s.note("backup", errOut)
	dns := dnsServers()
	if writeErr := os.WriteFile(pfConf, []byte(pfRules(staticIPs, resolved, dns)), 0644); writeErr != nil {
		return "", writeErr.Error()
	}
	_, errOut = runCmd("pfctl", "-f", pfConf)
	s.note("pfctl", errOut)
	_, errOut = runCmd("pfctl", "-e")
	s.note("pfctl-enable", errOut)
	if len(s.failed) > 0 {
		return "", summaryLine(staticIPs, names, dns, "", s.failed)
	}
	os.WriteFile(isolatedMarker, []byte("1"), 0644)

	refresh := ""
	if len(names) > 0 {
		writeLines(fqdnNamesFile, names)
		writeLines(fqdnIPsFile, resolved)
		writeLines(staticIPsFile, staticIPs)
		_, errOut = installRefreshTask()
		s.note("refresh-task", errOut)
		refresh = "com.clr.fqdn"
	}
	if len(s.failed) > 0 {
		return "", summaryLine(staticIPs, names, dns, refresh, s.failed)
	}
	return summaryLine(staticIPs, names, dns, refresh, nil), ""
}

func installRefreshTask() (string, string) {
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.clr.fqdn</string>
<key>ProgramArguments</key><array>
<string>%s</string><string>refresh</string>
</array>
<key>StartInterval</key><integer>60</integer>
</dict></plist>
`, selfExe())
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return "", err.Error()
	}
	out, errOut := runCmd("launchctl", "bootstrap", "system", plistPath)
	if errOut != "" {
		out2, err2 := runCmd("launchctl", "load", "-w", plistPath)
		return out + out2, err2
	}
	return out, errOut
}

func removeRefreshTask() {
	runCmd("launchctl", "bootout", "system/com.clr.fqdn")
	runCmd("launchctl", "unload", "-w", plistPath)
	os.Remove(plistPath)
}

func applyFQDN(_, _, all []string) error {
	if !isIsolated() {
		return errors.New("not isolated")
	}
	if len(all) == 0 {
		return errors.New("no addresses")
	}
	conf, err := os.ReadFile(pfConf)
	if err != nil {
		return err
	}
	if !strings.Contains(string(conf), "<clr_fqdn>") {
		body := pfRules(readLines(staticIPsFile), all, dnsServers())
		if err := os.WriteFile(pfConf, []byte(body), 0644); err != nil {
			return err
		}
		if _, errOut := runCmd("pfctl", "-f", pfConf); errOut != "" {
			return errors.New(errOut)
		}
		return nil
	}
	args := append([]string{"-t", "clr_fqdn", "-T", "replace"}, all...)
	if _, errOut := runCmd("pfctl", args...); errOut != "" {
		return errors.New(errOut)
	}
	return nil
}

func release() (string, string) {
	if !isIsolated() {
		return "", "The host is not isolated, or the backup has been removed."
	}
	resume := pauseRefresh()
	defer resume()
	if _, errOut := runCmd("cp", fwBackupFile, pfConf); errOut != "" {
		return "", "restore failed; backup kept at " + fwBackupFile
	}
	if _, errOut := runCmd("pfctl", "-f", pfConf); errOut != "" {
		return "", "restore failed; backup kept at " + fwBackupFile
	}
	os.Remove(fwBackupFile)
	os.Remove(isolatedMarker)
	os.Remove(fqdnNamesFile)
	os.Remove(fqdnIPsFile)
	os.Remove(staticIPsFile)
	removeRefreshTask()
	return "released", ""
}
