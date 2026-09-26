package main

import (
	"fmt"
	"net"
	"strings"
)

func parseResolvConf(text string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		ip := fields[1]
		if net.ParseIP(ip) == nil {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func parseScutilDNS(text string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver[") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		ip := strings.TrimSpace(parts[1])
		if net.ParseIP(ip) == nil {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func pfRules(static, fqdn, resolvers []string) string {
	var rules strings.Builder
	rules.WriteString("set skip on lo0\n")
	if len(fqdn) == 0 {
		rules.WriteString("table <clr_fqdn> persist\n")
	} else {
		rules.WriteString("table <clr_fqdn> persist { " + strings.Join(fqdn, ", ") + " }\n")
	}
	rules.WriteString("block all\n")
	for _, r := range resolvers {
		fmt.Fprintf(&rules, "pass out proto { udp tcp } to %s port 53\n", r)
	}
	for _, ip := range static {
		fmt.Fprintf(&rules, "pass in from %s\n", ip)
		fmt.Fprintf(&rules, "pass out to %s\n", ip)
	}
	rules.WriteString("pass in from <clr_fqdn>\n")
	rules.WriteString("pass out to <clr_fqdn>\n")
	return rules.String()
}
