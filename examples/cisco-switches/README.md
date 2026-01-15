# Cisco Switches Alerting

Real-time alerts for Cisco IOS/IOS-XE switches. This example focuses on **STP BPDU Guard violations** — a common and critical alert.

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

A BPDU Guard violation in VictoriaLogs:

```json
{
  "_time": "2026-01-15T10:52:01.935Z",
  "_msg": "1046: DC1-SW-ACCESS-01: Jan 15 10:52:01.935: %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/8 with BPDU Guard enabled. Disabling port.",
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
query: 'group:"SW" "SPANTREE-2-BLOCK_BPDUGUARD"'
```

- `group:"SW"` — filters only switch logs
- `"SPANTREE-2-BLOCK_BPDUGUARD"` — matches this specific alert

### 2. Parser Extracts Fields

```yaml
parser:
  json:
    fields: ["hostname", "site", "severity", "_msg", "level"]
  regex: '^\d+: (?P<switch_name>[A-Z0-9-]+):'
```

- JSON fields become template variables
- Regex extracts `switch_name` = `DC1-SW-ACCESS-01` from the message

### 3. Throttle Prevents Spam

```yaml
throttle:
  key: "{{ switch_name }}"
  count: 3
  window: 5m
```

- Groups alerts by switch name
- Max 3 notifications per 5 minutes per switch

### 4. Template Formats the Notification

```yaml
template: "bpdu_guard"
```

**Mattermost output:**

```markdown
🚨 BPDU Guard | DC1-SW-ACCESS-01 (10.255.40.25)

**Switch:** `DC1-SW-ACCESS-01` | **IP:** `10.255.40.25` | **Site:** `DC1`

​```
1046: DC1-SW-ACCESS-01: Jan 15 10:52:01.935: %SPANTREE-2-BLOCK_BPDUGUARD:
Received BPDU on port Gi1/0/8 with BPDU Guard enabled. Disabling port.
​```
```

## Other Cisco Alerts

The same logic applies to other Cisco syslog messages. Just change the query:

| Alert Type | Query |
|------------|-------|
| Hardware warnings | `group:"SW" "PLATFORM-4-ELEMENT_WARNING"` |
| SFP threshold | `group:"SW" "SFF8472-3-THRESHOLD_VIOLATION"` |
| VLAN mismatch | `group:"SW" "CDP-4-NATIVE_VLAN_MISMATCH"` |
| Stack link change | `group:"SW" "STACKMGR-4-STACK_LINK_CHANGE"` |
| Switch restart | `group:"SW" "SYS-5-RESTART"` |
| All critical (0-2) | `group:"SW" severity:~"[0-2]"` |

## Full Configuration

See [config.yaml](config.yaml) for the complete working configuration.
