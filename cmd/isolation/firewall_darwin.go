//go:build darwin

package main

import (
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
		return string(out), err.Error()
	}
	return string(out), ""
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

	var outs, errs []string

	stdout, stderr := runCmd("cp", pfConf, fwBackupFile)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	if err := os.WriteFile(pfConf, []byte(pfRules(staticIPs, resolved, len(names) > 0)), 0644); err != nil {
		return "", err.Error()
	}

	stdout, stderr = runCmd("pfctl", "-f", pfConf)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("pfctl", "-e")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	os.WriteFile(isolatedMarker, []byte("1"), 0644)

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

func pfRules(staticIPs, resolved []string, allowDNS bool) string {
	var rules strings.Builder
	rules.WriteString("block all\n")
	if allowDNS {
		rules.WriteString("pass out proto udp to any port 53\n")
		rules.WriteString("pass out proto tcp to any port 53\n")
		rules.WriteString("pass in proto udp from any port 53\n")
		rules.WriteString("pass in proto tcp from any port 53\n")
	}
	for _, ip := range append(append([]string{}, staticIPs...), resolved...) {
		rules.WriteString(fmt.Sprintf("pass in from %s\n", ip))
		rules.WriteString(fmt.Sprintf("pass out to %s\n", ip))
	}
	return rules.String()
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
	out, err := runCmd("launchctl", "bootstrap", "system", plistPath)
	if err != "" {
		out2, err2 := runCmd("launchctl", "load", "-w", plistPath)
		return out + out2, err2
	}
	return out, err
}

func removeRefreshTask() {
	runCmd("launchctl", "bootout", "system/com.clr.fqdn")
	runCmd("launchctl", "unload", "-w", plistPath)
	os.Remove(plistPath)
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
	if err := os.WriteFile(pfConf, []byte(pfRules(readLines(staticIPsFile), resolved, true)), 0644); err != nil {
		return
	}
	runCmd("pfctl", "-f", pfConf)
	writeLines(fqdnIPsFile, resolved)
}

func release() (string, string) {
	if !isIsolated() {
		return "", "The host is not isolated, or the backup has been removed."
	}

	var outs, errs []string

	stdout, stderr := runCmd("cp", fwBackupFile, pfConf)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("pfctl", "-f", pfConf)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	os.Remove(fwBackupFile)
	os.Remove(isolatedMarker)
	os.Remove(fqdnNamesFile)
	os.Remove(fqdnIPsFile)
	os.Remove(staticIPsFile)
	removeRefreshTask()

	return strings.Join(outs, " "), strings.Join(errs, " ")
}
