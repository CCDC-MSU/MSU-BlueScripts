# Analysis: Firewall User Filtering Issues

## Executive Summary

You have two related issues:
1. **Scope too narrow**: Only UID 0 (root) is allowed, but system services (UID 1-999) also need network access
2. **Filtering broken**: firewalld with nftables backend doesn't support user filtering via rich rules, leaving the security model ineffective on 4 hosts

Let me provide a detailed breakdown and solutions.

---

## Issue 1: Expand UID Range to System Users (< 1000)

### Background
On Linux systems, UIDs are conventionally allocated as:
- **UID 0**: root
- **UID 1-999**: System/service accounts (e.g., `nobody`, `_apt`, `dnsmasq`, `polkitd`)
- **UID 1000+**: Regular human users

When root runs `apt update` or `dnf install`, the package manager may spawn child processes that drop privileges to a service account. DNS resolution via `systemd-resolved` runs as `systemd-resolve` (typically UID 193 or similar).

### Current Implementation vs Required

| Backend | Current Code | Required Change |
|---------|--------------|-----------------|
| **iptables** | `-m owner --uid-owner 0` | `-m owner --uid-owner 0-999` |
| **nftables** | `meta skuid 0` | `meta skuid 0-999` or `meta skuid < 1000` |
| **ufw** | Injects iptables with `--uid-owner 0` | Same as iptables |
| **firewalld (iptables)** | `--uid-owner 0` in direct rules | Same as iptables |
| **firewalld (nftables)** | Rich rules (no user filter) | **Requires different approach** |
| **ipfw** | `uid 0` | `uid 0:999` |
| **pf** | No user filtering | No change possible |

### Implementation Details by Backend

#### iptables / ufw / firewalld-iptables
```bash
# Old
-m owner --uid-owner 0

# New
-m owner --uid-owner 0-999
```

The `owner` match module accepts ranges. This is well-supported.

#### nftables (direct)
```bash
# Old
meta skuid 0 ct state new,established accept

# New (Option A - range)
meta skuid 0-999 ct state new,established accept

# New (Option B - comparison)
meta skuid < 1000 ct state new,established accept
```

Both syntaxes work. Option B is slightly cleaner semantically.

#### ipfw (FreeBSD)
```bash
# Old
ipfw add 200 allow tcp from me to any 80 out uid 0 keep-state

# New
ipfw add 200 allow tcp from me to any 80 out uid 0:999 keep-state
```

---

## Issue 2: firewalld + nftables Backend Cannot Filter by User

### Root Cause Analysis

When firewalld runs with the nftables backend (default on Fedora 33+, RHEL 8+, Rocky, CentOS Stream, OpenSUSE Leap 15.3+), it manages rules through nftables but **does NOT expose user filtering capabilities** through its interfaces:

| firewalld Interface | User Filtering Support |
|--------------------|----------------------|
| Rich Rules | ❌ No `uid` or `skuid` option |
| Direct Rules (`--direct`) | ❌ Only works with iptables backend |
| Services/Zones | ❌ No user-level granularity |
| Policies (0.9.0+) | ❌ No user matching |

The script currently falls back to rich rules when nftables backend is detected:
```python
if uses_nftables:
    # Use rich rules for nftables backend (no user matching available)
    conn.sudo(
        f"firewall-cmd --zone=drop --add-rich-rule='"
        f"rule family=ipv4 port port={port} protocol={proto} accept'",
        ...
    )
```

This allows **ALL users** to access those ports, not just system users.

### Why This Happens

firewalld's architecture abstracts the backend, but its abstraction layer doesn't include all nftables features. Native nftables **does** support `meta skuid`, but firewalld's rich rule parser doesn't expose it.

```
┌─────────────────────────────────────────────────────────┐
│                    firewalld                            │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Rich Rules Parser                   │   │
│  │   Supports: source, destination, port, protocol │   │
│  │   Missing:  user/uid filtering                  │   │
│  └─────────────────────────────────────────────────┘   │
│                         │                               │
│            ┌────────────┴────────────┐                 │
│            ▼                         ▼                 │
│     iptables backend          nftables backend         │
│     (supports --uid-owner)    (supports meta skuid)    │
│                                but NOT exposed ↑       │
└─────────────────────────────────────────────────────────┘
```

---

## Proposed Solutions

### Solution A: Inject Native nftables Rules Alongside firewalld (Recommended)

**Approach**: Detect nftables backend, then inject rules directly via `nft` command into a custom table that firewalld doesn't manage.

**Pros**:
- Preserves firewalld for zone management
- User filtering works correctly
- No service restart required

**Cons**:
- Must be careful about rule ordering (priority)
- Rules may need to be reapplied if firewalld reloads

**Implementation**:

```python
def _apply_firewalld(self, conn):
    # ... existing detection code ...
    
    if uses_nftables and self.mode == MODE_ALLOW_INTERNET:
        # Inject native nftables rules for user filtering
        self._inject_nft_user_rules(conn)
    elif not uses_nftables and self.mode == MODE_ALLOW_INTERNET:
        # Use direct rules (iptables backend)
        self._apply_firewalld_direct_rules(conn)

def _inject_nft_user_rules(self, conn):
    """
    Inject native nftables rules for user-filtered internet access.
    Creates a separate table that coexists with firewalld's tables.
    """
    nft_commands = [
        # Create a custom table (won't conflict with firewalld's 'firewalld' table)
        "nft add table inet ccdc_internet",
        
        # Create output chain with priority -10 (runs BEFORE firewalld's output chain at priority 0)
        # Using 'accept' as policy since we only want to add specific accepts
        "nft add chain inet ccdc_internet output { type filter hook output priority -10 \\; }",
        
        # Create input chain for return traffic
        "nft add chain inet ccdc_internet input { type filter hook input priority -10 \\; }",
    ]
    
    # Add rules for each allowed port (system users only: uid < 1000)
    for port, protocols in INTERNET_PORTS.items():
        for proto in protocols:
            # Outbound: Allow system users (uid 0-999) to initiate
            nft_commands.append(
                f"nft add rule inet ccdc_internet output {proto} dport {port} "
                f"meta skuid 0-999 ct state new,established accept"
            )
            # Inbound: Allow established/related responses
            nft_commands.append(
                f"nft add rule inet ccdc_internet input {proto} sport {port} "
                f"ct state established,related accept"
            )
    
    for cmd in nft_commands:
        conn.sudo(cmd, hide=True, warn=True, timeout=10)
```

**Key Point**: The custom table with **priority -10** ensures our rules are evaluated BEFORE firewalld's rules (which use priority 0). If our rules accept the packet, it won't reach firewalld's drop rules.

**Cleanup/Revert**:
```bash
nft delete table inet ccdc_internet
```

---

### Solution B: Force iptables Backend on Affected Hosts

**Approach**: Modify `/etc/firewalld/firewalld.conf` to use iptables backend.

**Pros**:
- Direct rules with `--uid-owner` will work
- Consistent behavior across all firewalld hosts

**Cons**:
- Requires firewalld restart
- Some distros may have removed iptables entirely (Fedora 40+)
- May conflict with other tools expecting nftables

**Implementation**:

```python
def _force_iptables_backend(self, conn):
    """Switch firewalld to iptables backend if using nftables"""
    # Check if iptables is available
    if not conn.run("command -v iptables", warn=True, hide=True).ok:
        logger.warning("iptables not available, cannot switch backend")
        return False
    
    # Modify config
    conn.sudo(
        "sed -i 's/^FirewallBackend=.*/FirewallBackend=iptables/' "
        "/etc/firewalld/firewalld.conf",
        hide=True
    )
    
    # Restart firewalld
    conn.sudo("systemctl restart firewalld", hide=True, timeout=30)
    time.sleep(3)
    
    return True
```

**Not recommended** for production due to disruptiveness.

---

### Solution C: Bypass firewalld Entirely on nftables Systems

**Approach**: When nftables backend is detected and user filtering is needed, stop firewalld and manage nftables directly.

**Pros**:
- Full control over ruleset
- All nftables features available

**Cons**:
- Loses firewalld zone management
- May break other tools/services expecting firewalld
- More complex persistence handling

**Implementation**:

```python
def _apply_firewall_rules(self, conn, server_info):
    if self.active_backend == "firewalld":
        # Check if nftables backend AND we need user filtering
        if self._uses_nftables_backend(conn) and self.mode == MODE_ALLOW_INTERNET:
            logger.info("Switching from firewalld to direct nftables management")
            conn.sudo("systemctl stop firewalld", hide=True)
            conn.sudo("systemctl disable firewalld", warn=True, hide=True)
            self.active_backend = "nft"
            return self._apply_nft(conn)
        else:
            return self._apply_firewalld(conn)
```

---

### Solution D: Accept Limitation and Document

**Approach**: In `allow_internet` mode on firewalld+nftables, allow internet for all users (current behavior) but document the security trade-off.

**Implementation**:

```python
def _apply_firewalld(self, conn):
    # ...
    if uses_nftables and self.mode == MODE_ALLOW_INTERNET:
        logger.warning(
            "firewalld+nftables: User filtering unavailable. "
            "Internet access will be allowed for ALL users, not just system accounts."
        )
        # Apply rich rules without user filtering (current code)
```

**Not recommended** as it defeats the purpose of the restriction.

---

## Recommended Implementation Plan

### Phase 1: Fix UID Range (Quick Win)

Update all backends to use `0-999` instead of `0`:

```python
# Add constant at module level
SYSTEM_UID_MAX = 999  # UIDs 0-999 are system accounts

# In iptables rules:
f"-m owner --uid-owner 0-{SYSTEM_UID_MAX}"

# In nftables rules:
f"meta skuid 0-{SYSTEM_UID_MAX}"

# In ipfw rules:
f"uid 0:{SYSTEM_UID_MAX}"
```

### Phase 2: Fix firewalld+nftables (Solution A)

Implement the hybrid approach:

```python
def _apply_firewalld(self, conn):
    has_conntrack = self._ensure_conntrack_installed(conn)
    uses_nftables = self._detect_firewalld_backend(conn)
    
    try:
        # Standard firewalld setup (zones, trusted IPs)
        conn.sudo("firewall-cmd --reload", hide=True, timeout=30)
        conn.sudo("firewall-cmd --zone=trusted --add-interface=lo", warn=True, hide=True)
        
        for ip in TRUSTED_IPS:
            conn.sudo(f"firewall-cmd --zone=trusted --add-source={ip}", hide=True)
        
        conn.sudo("firewall-cmd --set-default-zone=drop", hide=True)
        
        # Handle allow_internet mode
        if self.mode == MODE_ALLOW_INTERNET:
            if uses_nftables:
                # Use native nftables for user filtering
                self._inject_nft_user_rules_for_firewalld(conn)
            else:
                # Use direct rules (iptables backend)
                self._apply_firewalld_direct_rules_iptables(conn)
        
        # Flush states
        self._flush_connection_states(conn, has_conntrack)
        
    except CommandTimedOut:
        # ... existing handling ...

def _inject_nft_user_rules_for_firewalld(self, conn):
    """
    Inject native nftables rules alongside firewalld for user-filtered internet.
    Uses a separate table with higher priority than firewalld.
    """
    logger.info("Injecting native nftables rules for user filtering (firewalld+nftables)")
    
    # Clean up any existing rules from previous runs
    conn.sudo("nft delete table inet ccdc_internet 2>/dev/null || true", hide=True)
    
    # Build ruleset
    rules = [
        "add table inet ccdc_internet",
        # Priority -10 = runs before firewalld (priority 0)
        "add chain inet ccdc_internet output { type filter hook output priority -10 ; }",
        "add chain inet ccdc_internet input { type filter hook input priority -10 ; }",
    ]
    
    for port, protocols in INTERNET_PORTS.items():
        for proto in protocols:
            rules.append(
                f"add rule inet ccdc_internet output {proto} dport {port} "
                f"meta skuid 0-{SYSTEM_UID_MAX} ct state new,established accept"
            )
            rules.append(
                f"add rule inet ccdc_internet input {proto} sport {port} "
                f"ct state established,related accept"
            )
    
    # Apply atomically via file
    ruleset = "\n".join(rules)
    conn.sudo(f"printf '%s' '{ruleset}' > /tmp/ccdc_internet.nft", hide=True)
    conn.sudo("nft -f /tmp/ccdc_internet.nft", hide=True, timeout=10)
    
    # Persist: Add to nftables include directory if available
    if conn.run("test -d /etc/nftables", warn=True, hide=True).ok:
        conn.sudo("cp /tmp/ccdc_internet.nft /etc/nftables/ccdc_internet.nft", hide=True)
        # Add include to main config if not present
        conn.sudo(
            "grep -q 'ccdc_internet.nft' /etc/sysconfig/nftables.conf || "
            "echo 'include \"/etc/nftables/ccdc_internet.nft\"' >> /etc/sysconfig/nftables.conf",
            warn=True, hide=True
        )
```

### Phase 3: Update Dead Man's Switch

Ensure DMS reverts the custom nftables table:

```python
def _arm_dead_mans_switch(self, conn, server_info):
    # ...
    if self.active_backend == "firewalld":
        # Check if we'll be using hybrid nftables
        if self._uses_nftables_backend(conn) and self.mode == MODE_ALLOW_INTERNET:
            revert_cmd = (
                "nft delete table inet ccdc_internet 2>/dev/null; "
                "firewall-cmd --set-default-zone=trusted && firewall-cmd --reload"
            )
        else:
            revert_cmd = "firewall-cmd --set-default-zone=trusted && firewall-cmd --reload"
```

---

## Testing Matrix

After implementation, verify:

| Host | Backend | Test | Expected Result |
|------|---------|------|-----------------|
| All | * | Root can `curl example.com` | ✅ 200 OK |
| All | * | Root can `apt/dnf update` | ✅ Success |
| All | * | System user (uid 65534) can resolve DNS | ✅ Success |
| All | * | User `sam` (uid 1000+) can `curl example.com` | ❌ Blocked |
| Fedora/Rocky/CentOS/OpenSUSE | firewalld+nft | User `sam` cannot access 104.18.26.120:80 | ❌ Connection refused |
| All | * | `su - sam -c "ping 8.8.8.8"` | ❌ Blocked (ICMP not in allowed ports) |

---

## Summary of Code Changes

| File Location | Change |
|--------------|--------|
| `firewall.py` (constants) | Add `SYSTEM_UID_MAX = 999` |
| `_apply_iptables()` | Change `--uid-owner 0` → `--uid-owner 0-999` |
| `_apply_nft()` | Change `meta skuid 0` → `meta skuid 0-999` |
| `_apply_ufw()` | Change `--uid-owner 0` → `--uid-owner 0-999` |
| `_apply_ipfw()` | Change `uid 0` → `uid 0:999` |
| `_apply_firewalld()` | Add nftables backend detection and call `_inject_nft_user_rules_for_firewalld()` |
| NEW: `_inject_nft_user_rules_for_firewalld()` | Implement hybrid nftables injection |
| `_arm_dead_mans_switch()` | Add cleanup for `ccdc_internet` table |