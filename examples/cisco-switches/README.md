# Cisco Switches Alerting

Real-time alerts for Cisco IOS/IOS-XE switches: STP errors, hardware warnings, stack changes, and restarts.

## Log Flow

```
Cisco Switch (syslog)
       ↓
VictoriaLogs
       ↓
Valerter (streams & alerts)
       ↓
Mattermost / Email
```

## Sample Log

A typical log entry in VictoriaLogs:

```json
{
  "_time": "2026-01-15T10:52:01.935Z",
  "_msg": "1046: Jan 15 10:52:01.935: %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/8 with BPDU Guard enabled. Disabling port.",
  "hostname": "10.255.40.25",
  "site": "DC1",
  "severity": "2",
  "level": "critical",
  "group": "SW"
}
```

## How Valerter Processes It

### 1. Query Matches the Log

```yaml
query: 'group:"SW" severity:~"[0-2]"'
```

- `group:"SW"` — filters only switch logs
- `severity:~"[0-2]"` — matches critical severities (0, 1, 2)

### 2. Parser Extracts Fields

```yaml
parser:
  json:
    fields: ["hostname", "site", "severity", "_msg", "level"]
  regex: '%(?P<alert_type>[A-Z0-9_-]+):'
```

- JSON fields become template variables
- Regex extracts `alert_type` = `SPANTREE-2-BLOCK_BPDUGUARD`

### 3. Throttle Prevents Spam

```yaml
throttle:
  key: "{{ hostname }}-{{ alert_type }}"
  count: 3
  window: 5m
```

- Groups alerts by switch + alert type
- Max 3 notifications per 5 minutes per key
- Different alert types on same switch → separate throttles

### 4. Template Formats the Notification

```yaml
template: "cisco_critical"
```

**Mattermost output:**

```markdown
🚨 CRITICAL | 10.255.40.25

**Site:** `DC1` | **Switch:** `10.255.40.25` | **Severity:** `CRITICAL`

​```
1046: Jan 15 10:52:01.935: %SPANTREE-2-BLOCK_BPDUGUARD:
Received BPDU on port Gi1/0/8 with BPDU Guard enabled. Disabling port.
​```
```

## Alert Types

| Rule | Query | What it catches |
|------|-------|-----------------|
| `cisco_sw_critical` | `severity:~"[0-2]"` | STP errors, security violations |
| `cisco_platform_warning` | `"PLATFORM-4-ELEMENT_WARNING"` | Fan, PSU, temperature |
| `cisco_sfp_threshold` | `"SFF8472-3-THRESHOLD_VIOLATION"` | Optical transceiver issues |
| `cisco_vlan_mismatch` | `"CDP-4-NATIVE_VLAN_MISMATCH"` | VLAN configuration issues |
| `cisco_stack_change` | `"STACKMGR-4-STACK_LINK_CHANGE"` | Stack topology changes |
| `cisco_restart` | `"SYS-5-RESTART"` | Switch reboots |

## Full Configuration

See [config.yaml](config.yaml) for the complete working configuration.
