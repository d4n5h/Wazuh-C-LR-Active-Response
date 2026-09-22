# Wazuh C-LR Active Response

**15 cross-platform active response modules** for Windows, Linux, and macOS.

## Modules Overview

| Module        | Purpose                        | Actions                                                            |
| ------------- | ------------------------------ | ------------------------------------------------------------------ |
| `isolation`   | Full network containment       | `isolate`, `release`                                               |
| `shell`       | Remote command execution       | —                                                                  |
| `collect`     | Forensic artifact collection   | `processes`, `connections`, `users`, `services`, `autoruns`, `all` |
| `kill`        | Process termination            | default, `tree`                                                    |
| `quarantine`  | File quarantine with metadata  | `quarantine`, `restore`, `delete`, `list`                          |
| `sysinfo`     | System profile snapshot        | —                                                                  |
| `user-mgmt`   | Local account control          | `disable`, `enable`, `logoff`                                      |
| `dns`         | Hosts-file domain blocking     | `block`, `unblock`, `list`                                         |
| `firewall`    | Granular firewall rules        | `block-ip`, `block-port`, `unblock`, `list`                        |
| `yara`        | YARA malware scan              | rules file path in `action`                                        |
| `hash`        | File hash lookup (SHA-256/MD5) | —                                                                  |
| `persistence` | Persistence hunting/removal    | `scan`, `remove`                                                   |
| `netconfig`   | Network cache/adapter reset    | `flush-dns`, `flush-arp`, `reset-adapter`                          |
| `log-collect` | On-demand log extraction       | `evtlog`, `journal`, `file`                                        |
| `integrity`   | On-demand file integrity check | `baseline`, `check`                                                |


All modules require `alert.data.user` for audit. Use `!module.exe` on Windows, `!module` on Linux/macOS.

Output is written to `active-responses.log` (viewable in Wazuh Discover). Large output is batched in 50-line chunks.

---

## Module Details

### Isolation

Network containment via platform-native firewalls. Blocks all traffic except whitelisted IPs (e.g. Wazuh manager).


| Platform | Backend                                  |
| -------- | ---------------------------------------- |
| Windows  | `netsh advfirewall`                      |
| Linux    | `nftables` (auto-fallback to `iptables`) |
| macOS    | `pfctl`                                  |



| Action    | `extra_args` | Description                         |
| --------- | ------------ | ----------------------------------- |
| `isolate` | IP/CIDR list | Block all traffic except listed IPs |
| `release` | —            | Restore original firewall state     |


Each exception IP must be the address the agent actually dials: the `<address>` in `ossec.conf`. On a VM talking to a cloud manager, that is the public IP, not the server's private or VPC address. If the agent can use IPv6, pass the AAAA address as well.

On Windows, isolate also allows outbound DNS (`remoteip=dns`) and DHCP (`remoteip=dhcp`) so a hostname can resolve and the VM keeps its address. Those rules do not open the rest of the network. `blockinbound,blockoutbound` still drops every other flow.

If the host is already isolated (`backup/fw_rules.xml` exists), `isolate` does nothing until `release` runs.

State stored in `<WarDir>/backup/`.

### Shell

Remote command execution with output batched back to Wazuh logs.


| Platform      | Executor     |
| ------------- | ------------ |
| Windows       | `cmd /c`     |
| Linux / macOS | `/bin/sh -c` |



| Parameter       | Description         |
| --------------- | ------------------- |
| `extra_args[0]` | Full command string |


### Collect

Curated forensic data collection — repeatable triage without per-OS commands.


| Action        | Data collected     | Windows              | Linux         | macOS              |
| ------------- | ------------------ | -------------------- | ------------- | ------------------ |
| `processes`   | Running processes  | `tasklist`           | `ps aux`      | `ps aux`           |
| `connections` | Active connections | `netstat -ano`       | `ss -tunap`   | `netstat` / `lsof` |
| `users`       | Logged-in sessions | `query user`         | `who` / `w`   | `who` / `w`        |
| `services`    | Running services   | `sc query`           | `systemctl`   | `launchctl list`   |
| `autoruns`    | Persistence items  | `schtasks`, registry | cron, systemd | LaunchAgents       |
| `all`         | All of the above   |                      |               |                    |


### Kill

Terminate a process by PID or image name.


| Parameter           | Description                                                 |
| ------------------- | ----------------------------------------------------------- |
| `extra_args[0]`     | PID (numeric) or process name                               |
| `alert.data.action` | `tree` to kill entire process tree; omit for single process |



| Platform | Backend                                    |
| -------- | ------------------------------------------ |
| Windows  | `taskkill /F /PID` or `/IM`, `/T` for tree |
| Linux    | `kill -9`, tree via `/proc/<pid>/children` |
| macOS    | `kill -9`, tree via `pgrep -P`             |


### Quarantine

Move suspicious files to a secure quarantine directory with SHA-256 metadata.


| Action       | `extra_args`  | Description                                         |
| ------------ | ------------- | --------------------------------------------------- |
| `quarantine` | file path     | Hash, move to `<WarDir>/quarantine/`, save metadata |
| `restore`    | quarantine ID | Move file back to original path                     |
| `delete`     | quarantine ID | Permanently delete quarantined file                 |
| `list`       | —             | List all quarantined files with metadata            |


Quarantined files are chmod 000. Metadata JSON per file includes `original_path`, `sha256`, `quarantined_at`, `user`, `size`, `id`.

### Sysinfo

One-shot system profile for triage: OS version, interfaces, DNS, patches, disk, memory. No action required — runs automatically on invocation.

### User-mgmt

Local account management during incident response.


| Action    | `extra_args[0]`                     | Windows                | Linux        | macOS                                       |
| --------- | ----------------------------------- | ---------------------- | ------------ | ------------------------------------------- |
| `disable` | username                            | `net user /active:no`  | `usermod -L` | `pwpolicy -setpolicy newPasswordRequired=1` |
| `enable`  | username                            | `net user /active:yes` | `usermod -U` | `pwpolicy -setpolicy newPasswordRequired=0` |
| `logoff`  | session ID (Win) or username (Unix) | `logoff`               | `pkill -u`   | `pkill -u`                                  |


### DNS

Lightweight C2 cutoff via hosts file — no full network isolation.


| Action    | `extra_args`                   | Description                                |
| --------- | ------------------------------ | ------------------------------------------ |
| `block`   | domain list                    | Append `127.0.0.1 <domain> # C-LR` entries |
| `unblock` | domain list (or empty for all) | Remove C-LR tagged entries                 |
| `list`    | —                              | Show current blocks                        |


Hosts file: Windows `C:\Windows\System32\drivers\etc\hosts`, Linux/macOS `/etc/hosts`. Linux and macOS automatically flush DNS cache after edits.

### Firewall

Surgical per-IP/port rules — unlike `isolation` which replaces the entire ruleset.


| Action       | `extra_args`           | Description                   |
| ------------ | ---------------------- | ----------------------------- |
| `block-ip`   | IP or CIDR             | Block inbound+outbound for IP |
| `block-port` | `port` or `port:proto` | Block port (default TCP)      |
| `unblock`    | rule label             | Remove a C-LR rule            |
| `list`       | —                      | List C-LR-managed rules       |



| Platform | Backend                                          |
| -------- | ------------------------------------------------ |
| Windows  | `netsh advfirewall` (rules prefixed `C-LR-`)     |
| Linux    | `nftables` or `iptables`                         |
| macOS    | `pfctl` (rules in `<WarDir>/firewall/clr.rules`) |


### Yara

Scan files/directories against YARA rules. Requires `yara` CLI in PATH.


| Parameter           | Description               |
| ------------------- | ------------------------- |
| `alert.data.action` | Path to YARA rules file   |
| `extra_args[0]`     | File or directory to scan |


### Hash

Compute SHA-256 and MD5 hashes for IOC comparison. Pure stdlib, no platform-specific code.


| Parameter    | Description            |
| ------------ | ---------------------- |
| `extra_args` | One or more file paths |


Returns JSON array: `[{"path":"...","sha256":"...","md5":"...","size":12345}]`

### Persistence

Deep persistence hunting beyond `collect autoruns`. Scan and optionally remove entries.


| Action   | `extra_args`         | Description                                  |
| -------- | -------------------- | -------------------------------------------- |
| `scan`   | —                    | Enumerate startup, scheduled tasks, services |
| `remove` | `[type, identifier]` | Remove entry by type and ID                  |


Remove types:


| Platform | Types                                 |
| -------- | ------------------------------------- |
| Windows  | `scheduled`, `service`, `runkey`      |
| Linux    | `cron`, `service`, `timer`            |
| macOS    | `launchagent`, `launchdaemon`, `cron` |


### Netconfig

Quick network resets for DNS poisoning or ARP spoofing response.


| Action          | `extra_args[0]` | Description                        |
| --------------- | --------------- | ---------------------------------- |
| `flush-dns`     | —               | Clear DNS resolver cache           |
| `flush-arp`     | —               | Clear ARP table                    |
| `reset-adapter` | interface name  | Bounce network interface (down/up) |


### Log-collect

On-demand log extraction, batched back to Wazuh.


| Action    | `extra_args`       | Platform | Description                                        |
| --------- | ------------------ | -------- | -------------------------------------------------- |
| `evtlog`  | `[channel, count]` | Windows  | Query Event Log via `wevtutil` (default 50 events) |
| `journal` | `[unit, count]`    | Linux    | Query systemd journal (default 50 lines)           |
| `file`    | `[path, count]`    | All      | Tail log file (default 50 lines)                   |


Example: `arguments: ["Security", "100"]` for last 100 Security events.

### Integrity

Analyst-triggered file integrity monitoring complementing Wazuh FIM.


| Action     | `extra_args`         | Description                                                                 |
| ---------- | -------------------- | --------------------------------------------------------------------------- |
| `baseline` | `[label, root_path]` | Hash all files in directory tree, save to `<WarDir>/integrity/<label>.json` |
| `check`    | `[label]`            | Re-hash and diff against baseline (added/modified/deleted)                  |


Returns JSON diff: `{"label":"...","added":[],"modified":[],"deleted":[]}`

## Build

Requires Go 1.21+. For legacy Windows (Server 2008 R2), also install Go 1.20:

```powershell
go install golang.org/dl/go1.20.14@latest
go1.20.14 download
```

Build all 7 targets:

```powershell
.\build.ps1
```

```bash
chmod +x build.sh   # first time only
./build.sh          # optional: ./build.sh dist
```

### Output

```text
bin/
├── legacy-amd64/     # Windows Server 2008 R2+ / Win7+ (Go 1.20)
├── windows-amd64/    # Windows Server 2016+ / Win10+
├── windows-arm64/    # Windows 11 ARM
├── linux-amd64/
├── linux-arm64/
├── darwin-amd64/
└── darwin-arm64/
```

Each folder contains all 15 modules (with `.exe` extension on Windows):

`isolation`, `shell`, `collect`, `kill`, `quarantine`, `sysinfo`, `user-mgmt`, `dns`, `firewall`, `yara`, `hash`, `persistence`, `netconfig`, `log-collect`, `integrity`

## Binary Compatibility Guide

### Windows


| Binary           | OS Versions                                                                 |
| ---------------- | --------------------------------------------------------------------------- |
| `legacy-amd64/`  | Windows 7, 8, 8.1, 10, 11 / Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022 |
| `windows-amd64/` | Windows 10 1809+, 11 / Server 2016, 2019, 2022, 2025                        |
| `windows-arm64/` | Windows 11 ARM / Server 2025 ARM                                            |


Use **legacy-amd64** if you have any endpoints running Server 2008 R2 through 2012 R2 or Windows 7/8.x. For anything Server 2016 or newer, use **windows-amd64** (smaller, faster binary built with latest Go).

### Linux


| Binary         | Architecture | Distros                                                 |
| -------------- | ------------ | ------------------------------------------------------- |
| `linux-amd64/` | x86_64       | Ubuntu, Debian, RHEL, CentOS, Rocky, Amazon Linux, SLES |
| `linux-arm64/` | aarch64      | AWS Graviton, Raspberry Pi 4+, Oracle ARM               |


Firewall backend is auto-detected at runtime: `nftables` if `nft` is in PATH, otherwise falls back to `iptables`.

### macOS


| Binary          | Architecture  | Hardware                        |
| --------------- | ------------- | ------------------------------- |
| `darwin-amd64/` | Intel x86_64  | MacBook/iMac/Mac Pro (pre-2020) |
| `darwin-arm64/` | Apple Silicon | M1, M2, M3, M4+                 |


Apple Silicon Macs can also run `darwin-amd64` via Rosetta 2, but prefer the native `darwin-arm64` binary.

## Deploy

Copy the appropriate binaries for each module to the Wazuh active-response directory. All 15 modules can be deployed together or selectively.


| Platform | Path                                                      |
| -------- | --------------------------------------------------------- |
| Windows  | `C:\Program Files (x86)\ossec-agent\active-response\bin\` |
| Linux    | `/var/ossec/active-response/bin/`                         |
| macOS    | `/Library/Ossec/active-response/bin/`                     |


Each module must also be registered in the Wazuh agent `ossec.conf` under `<active-response>` if not already configured. Example:

```xml
<command>isolation.exe</command>
<timeout_allowed>yes</timeout_allowed>
```

Repeat for each deployed module (`collect.exe`, `kill.exe`, etc.).

Restart the Wazuh agent:

```powershell
# Windows
Restart-Service -Name wazuh

# Linux / macOS
systemctl restart wazuh-agent
```

## Usage (Wazuh API)

Commands are sent via the Wazuh API (`PUT /active-response`) from the DevTools console or any API client.

### Common Parameters


| Parameter           | Description                                        |
| ------------------- | -------------------------------------------------- |
| `agents_list`       | Agent ID(s), comma-separated                       |
| `command`           | `!module.exe` (Windows) or `!module` (Linux/macOS) |
| `arguments`         | Passed as `extra_args` to the binary               |
| `alert.data.action` | Module-specific action (see each module)           |
| `alert.data.user`   | Analyst identity — **required** on all modules     |
| `alert.data.debug`  | Write raw input to `<module>.log` in `<WarDir>/`   |


Debug log and state file locations:


| Platform | WarDir                                                |
| -------- | ----------------------------------------------------- |
| Windows  | `C:\Program Files (x86)\ossec-agent\active-response\` |
| Linux    | `/var/ossec/active-response/`                         |
| macOS    | `/Library/Ossec/active-response/`                     |


---

### Isolation

Contain a compromised host by blocking all network traffic except to whitelisted IPs (e.g. Wazuh manager). Restore with `release`.

Pass the manager address from the agent's `ossec.conf` `<address>` (cloud public IP when the agent is a local VM). Windows also allows DNS and DHCP so that address can still be reached. Re-run `release` before `isolate` if the host is already isolated.

**Isolate:**

```json
PUT /active-response?agents_list=001
{
  "command": "!isolation.exe",
  "arguments": ["192.168.1.1", "192.168.1.2"],
  "alert": {
    "data": {
      "action": "isolate",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Release:**

```json
PUT /active-response?agents_list=001
{
  "command": "!isolation.exe",
  "arguments": [],
  "alert": {
    "data": {
      "action": "release",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

---

### Shell

Execute CMD, PowerShell, or shell commands remotely. Output batched into 50-line chunks.

**Windows CMD:**

```json
PUT /active-response?agents_list=001
{
  "command": "!shell.exe",
  "arguments": ["cmd /c net user"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Windows PowerShell:**

```json
PUT /active-response?agents_list=001
{
  "command": "!shell.exe",
  "arguments": ["powershell -c Get-NetTCPConnection -State Established"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Linux / macOS:**

```json
PUT /active-response?agents_list=002
{
  "command": "!shell",
  "arguments": ["ps aux | grep suspicious"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

---

### Collect

**All forensic artifacts:**

```json
PUT /active-response?agents_list=001
{
  "command": "!collect.exe",
  "arguments": [],
  "alert": {
    "data": {
      "action": "all",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Single artifact type** (`processes`, `connections`, `users`, `services`, `autoruns`):

```json
PUT /active-response?agents_list=001
{
  "command": "!collect.exe",
  "arguments": [],
  "alert": {
    "data": {
      "action": "processes",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

---

### Kill

**Kill by PID:**

```json
PUT /active-response?agents_list=001
{
  "command": "!kill.exe",
  "arguments": ["1234"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Kill process tree:**

```json
PUT /active-response?agents_list=001
{
  "command": "!kill.exe",
  "arguments": ["1234"],
  "alert": {
    "data": {
      "action": "tree",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Kill by process name:**

```json
PUT /active-response?agents_list=001
{
  "command": "!kill.exe",
  "arguments": ["malware.exe"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

---

### Quarantine

**Quarantine a file:**

```json
PUT /active-response?agents_list=001
{
  "command": "!quarantine.exe",
  "arguments": ["C:\\Users\\Public\\suspect.exe"],
  "alert": {
    "data": {
      "action": "quarantine",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Restore / delete / list:**

```json
PUT /active-response?agents_list=001
{
  "command": "!quarantine.exe",
  "arguments": ["abc123def4567890"],
  "alert": {
    "data": {
      "action": "restore",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

Use `"action": "delete"` to permanently remove, or `"action": "list"` with empty `arguments` to list all quarantined files.

---

### Sysinfo

```json
PUT /active-response?agents_list=001
{
  "command": "!sysinfo.exe",
  "arguments": [],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

---

### User-mgmt

**Disable account:**

```json
PUT /active-response?agents_list=001
{
  "command": "!user-mgmt.exe",
  "arguments": ["compromised_user"],
  "alert": {
    "data": {
      "action": "disable",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

Actions: `disable`, `enable`, `logoff`. `extra_args[0]` = target username (Windows logoff uses session ID).

---

### DNS

**Block domains:**

```json
PUT /active-response?agents_list=001
{
  "command": "!dns.exe",
  "arguments": ["evil.com", "c2.bad.io"],
  "alert": {
    "data": {
      "action": "block",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Unblock / list:**

```json
PUT /active-response?agents_list=001
{
  "command": "!dns.exe",
  "arguments": ["evil.com"],
  "alert": {
    "data": {
      "action": "unblock",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

Use `"action": "list"` with empty `arguments` to show all blocked domains.

---

### Firewall

**Block IP:**

```json
PUT /active-response?agents_list=001
{
  "command": "!firewall.exe",
  "arguments": ["203.0.113.50"],
  "alert": {
    "data": {
      "action": "block-ip",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Block port:**

```json
PUT /active-response?agents_list=001
{
  "command": "!firewall.exe",
  "arguments": ["4444:tcp"],
  "alert": {
    "data": {
      "action": "block-port",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Unblock / list:** use `"action": "unblock"` with rule label in `arguments`, or `"action": "list"`.

---

### Yara

Requires `yara` CLI installed on the endpoint.

```json
PUT /active-response?agents_list=001
{
  "command": "!yara.exe",
  "arguments": ["C:\\Users\\Public"],
  "alert": {
    "data": {
      "action": "C:\\rules\\malware.yar",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

`alert.data.action` = rules file path, `arguments[0]` = scan target (file or directory).

---

### Hash

**Single or multiple files:**

```json
PUT /active-response?agents_list=001
{
  "command": "!hash.exe",
  "arguments": ["C:\\Users\\Public\\suspect.exe", "C:\\Temp\\payload.dll"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Linux / macOS:**

```json
PUT /active-response?agents_list=002
{
  "command": "!hash",
  "arguments": ["/tmp/suspect.bin"],
  "alert": {
    "data": {
      "user": "johndoe",
      "debug": false
    }
  }
}
```

---

### Persistence

**Scan:**

```json
PUT /active-response?agents_list=001
{
  "command": "!persistence.exe",
  "arguments": [],
  "alert": {
    "data": {
      "action": "scan",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Remove entry:**

```json
PUT /active-response?agents_list=001
{
  "command": "!persistence.exe",
  "arguments": ["scheduled", "\\\\MaliciousTask"],
  "alert": {
    "data": {
      "action": "remove",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

Types: Windows `scheduled`, `service`, `runkey` — Linux `cron`, `service`, `timer` — macOS `launchagent`, `launchdaemon`, `cron`.

---

### Netconfig

**Flush DNS:**

```json
PUT /active-response?agents_list=001
{
  "command": "!netconfig.exe",
  "arguments": [],
  "alert": {
    "data": {
      "action": "flush-dns",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Reset adapter** (`extra_args[0]` = interface name):

```json
PUT /active-response?agents_list=001
{
  "command": "!netconfig.exe",
  "arguments": ["Ethernet"],
  "alert": {
    "data": {
      "action": "reset-adapter",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

Also supports `"action": "flush-arp"`.

---

### Log-collect

**Windows Event Log:**

```json
PUT /active-response?agents_list=001
{
  "command": "!log-collect.exe",
  "arguments": ["Security", "100"],
  "alert": {
    "data": {
      "action": "evtlog",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Linux systemd journal:**

```json
PUT /active-response?agents_list=002
{
  "command": "!log-collect",
  "arguments": ["sshd", "50"],
  "alert": {
    "data": {
      "action": "journal",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Tail log file (all platforms):**

```json
PUT /active-response?agents_list=002
{
  "command": "!log-collect",
  "arguments": ["/var/log/auth.log", "100"],
  "alert": {
    "data": {
      "action": "file",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

---

### Integrity

**Create baseline:**

```json
PUT /active-response?agents_list=001
{
  "command": "!integrity.exe",
  "arguments": ["webroot", "C:\\inetpub\\wwwroot"],
  "alert": {
    "data": {
      "action": "baseline",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

**Check against baseline:**

```json
PUT /active-response?agents_list=001
{
  "command": "!integrity.exe",
  "arguments": ["webroot"],
  "alert": {
    "data": {
      "action": "check",
      "user": "johndoe",
      "debug": false
    }
  }
}
```

`arguments[0]` = baseline label. For `baseline`, `arguments[1]` = root directory to hash.

## Project Structure

```
├── build.ps1
├── build.sh
├── go.mod
├── cmd/
│   ├── isolation/
│   ├── shell/
│   ├── collect/
│   ├── kill/
│   ├── quarantine/
│   ├── sysinfo/
│   ├── user-mgmt/
│   ├── dns/
│   ├── firewall/
│   ├── yara/
│   ├── hash/
│   ├── persistence/
│   ├── netconfig/
│   ├── log-collect/
│   └── integrity/
└── internal/
    └── shared/
        ├── shared.go
        ├── batch.go
        ├── exec_windows.go
        ├── exec_unix.go
        ├── paths_windows.go
        ├── paths_linux.go
        └── paths_darwin.go
```

