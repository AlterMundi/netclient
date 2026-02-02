# Persistent Local ACL Rules for Netclient: Host Sovereignty in Public-IP Mesh Networks

**Branch:** `policy-routing`
**Author:** AlterMundi / 44mesh
**Date:** February 2026

---

## 1. Context: Why Netmaker Is Routing Public IPs Through WireGuard

AlterMundi operates community networks in Argentina and Latin America. Through
the **44mesh** project, we are connecting community network nodes to an Internet
Exchange Point (IXP) and distributing **globally routable public IP addresses**
to remote nodes via a Netmaker WireGuard mesh.

The topology:

```
                    ┌─────────────────────────────┐
                    │         IXP (CABASE)         │
                    │   BGP announces 138.255.89/24│
                    └─────────┬───────────────────-┘
                              │ public peering
                    ┌─────────┴───────────────────-┐
                    │     Border Router (egress)    │
                    │  Netmaker node + BGP speaker  │
                    │  announces 0.0.0.0/0 as egress│
                    └─────────┬───────────────────-┘
                              │ WireGuard tunnel
               ┌──────────────┼──────────────────┐
               │              │                  │
        ┌──────┴──────┐ ┌────┴──────┐ ┌────────┴──────┐
        │  Node A     │ │  Node B   │ │  Node C       │
        │ 138.255.89.1│ │ .89.2     │ │ .89.3         │
        │ rural site  │ │ school    │ │ health clinic  │
        └─────────────┘ └───────────┘ └───────────────┘
```

Each remote node receives a `/32` public IP address from the `138.255.89.0/24`
block. The Netmaker server advertises `0.0.0.0/0` as an egress range, and
source-based policy routing (commit `ff2ec0bf`) ensures that:

- **Inbound internet traffic** destined for `138.255.89.x` arrives at the
  border router via BGP, gets forwarded through the WireGuard tunnel via
  Netmaker's cryptokey routing, and reaches the node.
- **Outbound responses** from the node's VPN IP route back through the tunnel
  via a policy routing table (`ip rule from 138.255.89.x lookup table 112`).
- **Normal browsing** from the node's LAN IP uses the local ISP gateway
  unchanged.

This is, to our knowledge, the first deployment using Netmaker to distribute
**routable public IP space** from an IXP to endpoints. It works. But it
surfaces a security assumption in netclient's firewall management that becomes
dangerous in this topology.

---

## 2. The Problem: `AllowAll=true` Means No Firewall

When the Netmaker server's ACL policy is set to allow all traffic between nodes
(the default for most deployments), the server sends `FwUpdate.AllowAll=true` to
every node on every sync cycle. The netclient daemon processes this in
`firewall/acl.go:11`:

```go
// firewall/acl.go:15-23 (BEFORE this patch)
if fwUpdate.AllowAll {
    fwCrtl.ChangeACLInTarget(targetAccept)    // line 16
    fwCrtl.ChangeACLFwdTarget(targetAccept)   // line 17
} else {
    fwCrtl.ChangeACLInTarget(targetDrop)
    fwCrtl.ChangeACLFwdTarget(targetDrop)
}
```

`ChangeACLInTarget(targetAccept)` sets the last rule in `NETMAKER-ACL-IN` to:

```
-i netmaker -m comment --comment NETMAKER -j ACCEPT
```

This rule appears in the `INPUT` chain path (via a jump rule at
`iptables_linux.go:80-84`). It matches **every packet arriving on the
`netmaker` WireGuard interface** and ACCEPTs it. The effect: any service
listening on any port — SSH, databases, admin panels — is fully exposed to
everything routed through the tunnel.

In a private mesh where all IPs are RFC1918, this is an acceptable trade-off:
you trust the mesh. But in our topology, the `netmaker` interface carries
**internet-routable traffic**. The `138.255.89.0/24` addresses are reachable
from the entire internet via the IXP BGP announcement. The blanket ACCEPT means
the node's SSH daemon, for example, is exposed not just to other mesh nodes but
to **anyone on the public internet** whose traffic reaches the border router.

Worse: the blanket ACCEPT is **re-applied on every sync**. The `ProcessAclRules`
function is called from three paths (`functions/mqhandlers.go:391`,
`functions/mqhandlers.go:955`, `functions/daemon.go:342`), each triggered by
MQTT messages, HTTP fallback pulls, or periodic polling. Manual `iptables` fixes
get overwritten within seconds.

### The overwrite cycle

```
Admin adds:  iptables -I NETMAKER-ACL-IN -i netmaker -p tcp --dport 22 -j DROP
                                    ↓
MQTT sync fires (every ~15s):
  ProcessAclRules() →
    ChangeACLInTarget("ACCEPT") →
      Deletes any DROP rule, appends ACCEPT
                                    ↓
Result: SSH is exposed again
```

---

## 3. The Solution: Local ACL Config File

This patch introduces a file-based local ACL override at
`/etc/netclient/local-acl.json`. When present and enabled, it intercepts the
`AllowAll=true` path and replaces the blanket ACCEPT with:

1. Specific per-source, per-protocol, per-port ACCEPT rules
2. An optional LOG rule for dropped traffic
3. A default DROP for everything else

The file is re-read on every sync cycle, so changes take effect within seconds
without restarting the daemon. No file or `enabled: false` produces the original
behavior — zero impact on existing deployments.

### Config file format

```json
{
    "enabled": true,
    "log_dropped": true,
    "log_prefix": "NETMAKER-ACL-DROP: ",
    "rules": [
        {"source": "138.255.89.0/24", "protocol": "icmp", "port": "",   "comment": "ping from mesh"},
        {"source": "138.255.89.0/24", "protocol": "tcp",  "port": "80", "comment": "HTTP from mesh"},
        {"source": "138.255.89.0/24", "protocol": "udp",  "port": "53", "comment": "DNS from mesh"},
        {"source": "10.10.0.0/16",    "protocol": "",     "port": "",   "comment": "allow all from management VLAN"}
    ]
}
```

### Resulting iptables state

```
Chain NETMAKER-ACL-IN (jumped to from INPUT):
 num  target     prot opt source               destination
 1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0   tcp dpt:51722 comment "NETMAKER"   ← metrics port (from addJumpRules)
 2    ACCEPT     udp  --  0.0.0.0/0            0.0.0.0/0   udp dpt:53 comment "NETMAKER"      ← DNS (from addJumpRules)
 3    ACCEPT     icmp --  138.255.89.0/24      0.0.0.0/0   comment "NETMAKER-LOCAL-ACL"        ← local rule
 4    ACCEPT     tcp  --  138.255.89.0/24      0.0.0.0/0   tcp dpt:80 comment "NETMAKER-LOCAL-ACL"
 5    ACCEPT     udp  --  138.255.89.0/24      0.0.0.0/0   udp dpt:53 comment "NETMAKER-LOCAL-ACL"
 6    ACCEPT     all  --  10.10.0.0/16         0.0.0.0/0   comment "NETMAKER-LOCAL-ACL"
 7    LOG        all  --  0.0.0.0/0            0.0.0.0/0   comment "NETMAKER-LOCAL-ACL" LOG "NETMAKER-ACL-DROP: "
 8    DROP       all  --  0.0.0.0/0            0.0.0.0/0   -i netmaker comment "NETMAKER"      ← default deny
```

SSH, databases, and all other services: silently dropped (or logged, then
dropped). Only the explicit allowlist passes through.

---

## 4. Code Walkthrough

### 4.1 New file: `firewall/local_acl.go`

This file defines the data model and config loader. It has no dependencies on
iptables or nftables — it is pure config parsing.

```go
// firewall/local_acl.go:13
const localACLComment = "NETMAKER-LOCAL-ACL"
```

The distinct comment tag is critical. Netmaker's existing rules use `NETMAKER` as
their iptables comment (`iptables_linux.go:30`). By tagging local ACL rules with
`NETMAKER-LOCAL-ACL`, we can cleanly identify, remove, and re-insert them on
every sync without touching server-managed rules.

```go
// firewall/local_acl.go:33-48
func LoadLocalACLConfig() *LocalACLConfig {
    path := filepath.Join(config.GetNetclientPath(), "local-acl.json")
    data, err := os.ReadFile(path)
    if err != nil {
        if !os.IsNotExist(err) {
            slog.Warn("failed to read local ACL config", "path", path, "error", err)
        }
        return nil  // file doesn't exist → original behavior
    }
    var cfg LocalACLConfig
    if err := json.Unmarshal(data, &cfg); err != nil {
        slog.Warn("failed to parse local ACL config", "path", path, "error", err)
        return nil  // malformed → original behavior (fail-open for compatibility)
    }
    return &cfg
}
```

**Design choice: fail-open vs fail-closed.** If the file is missing or
malformed, we return `nil`, which means the original `AllowAll → ACCEPT`
behavior applies. This is intentional — we do not want a typo in a config file
to lock an operator out of a remote node with no physical access. The local ACL
is an opt-in security hardening, not a mandatory gate.

### 4.2 Modified: `firewall/acl.go` — the decision point

```go
// firewall/acl.go:17-27
localACL := LoadLocalACLConfig()
if fwUpdate.AllowAll && localACL != nil && localACL.Enabled && len(localACL.Rules) > 0 {
    slog.Info("44mesh: local ACL rules override server AllowAll")
    fwCrtl.ApplyLocalACLRules(localACL)
} else if fwUpdate.AllowAll {
    fwCrtl.ChangeACLInTarget(targetAccept)
    fwCrtl.ChangeACLFwdTarget(targetAccept)
} else {
    fwCrtl.ChangeACLInTarget(targetDrop)
    fwCrtl.ChangeACLFwdTarget(targetDrop)
}
```

Four conditions must all be true to engage the override:
1. Server says `AllowAll=true`
2. Config file exists and was parsed
3. `enabled: true` in the JSON
4. At least one rule is defined

This means:
- **Server-managed ACLs (AllowAll=false)** are completely unaffected. The
  `else` branch sets DROP as the default and server ACL rules provide specific
  ACCEPTs — exactly as before.
- **AllowAll=true without a config file** produces the original blanket ACCEPT.
- **AllowAll=true with local ACL** uses the local rules.

The rest of `ProcessAclRules` (lines 29-69) runs unchanged in all cases — server
ACL rules are still added, updated, and deleted normally. The local ACL only
controls the **default policy** (what happens to packets that don't match any
server ACL rule).

### 4.3 Modified: `firewall/firewall.go` — interface contract

```go
// firewall/firewall.go:84-85
// ApplyLocalACLRules - applies local ACL rules overriding the blanket ACCEPT
ApplyLocalACLRules(cfg *LocalACLConfig)
```

Added to the `firewallController` interface so both iptables and nftables
backends must implement it. This follows the existing pattern for every firewall
operation in netclient.

### 4.4 Modified: `firewall/iptables_linux.go` — the implementation

This is the core of the patch. Four methods on `iptablesManager`:

#### `ApplyLocalACLRules` — orchestrator (`iptables_linux.go:226-274`)

```go
func (i *iptablesManager) ApplyLocalACLRules(cfg *LocalACLConfig) {
    // 1. Clean slate: remove any existing local ACL rules
    i.removeLocalACLRules(i.ipv4Client)
    i.removeLocalACLRules(i.ipv6Client)

    // 2. Set DROP as the default target (replaces any ACCEPT)
    i.ChangeACLInTarget(targetDrop)
    i.ChangeACLFwdTarget(targetDrop)

    // 3. Insert LOG rule before DROP if requested
    if cfg.LogDropped { ... }

    // 4. Insert ACCEPT rules in reverse order (so they appear in config order)
    for j := len(cfg.Rules) - 1; j >= 0; j-- { ... }
}
```

The method is called on every sync cycle. The idempotent clean-then-rebuild
pattern means it doesn't matter how many times it runs — the resulting chain
state is always consistent with the current config file contents.

**Why reverse iteration (step 4)?** Each rule is inserted at the position just
before the DROP rule. Inserting in reverse order means the first rule in the
config file ends up closest to the top of the chain — preserving the natural
reading order. This matches how an operator would think about the rules: first
match wins.

**IPv4/IPv6 dispatch.** Each rule's `source` CIDR is checked with `isAddrIpv4()`
(`firewall/utils.go:10`) to route it to the correct iptables client:

```go
// iptables_linux.go:256-262
isV4 := isAddrIpv4(rule.Source)
var client *iptables.IPTables
if isV4 {
    client = i.ipv4Client
} else {
    client = i.ipv6Client
}
```

This is important for dual-stack deployments where some mesh traffic is IPv6.

#### `removeLocalACLRules` — cleanup (`iptables_linux.go:277-293`)

```go
func (i *iptablesManager) removeLocalACLRules(client *iptables.IPTables) {
    for _, chain := range []string{aclInputRulesChain, aclFwdRulesChain} {
        rules, err := client.List(defaultIpTable, chain)
        if err != nil { continue }
        for _, rule := range rules {
            if containsComment(rule, localACLComment) {
                fields := strings.Fields(rule)
                if len(fields) > 2 { fields = fields[2:] }
                client.Delete(defaultIpTable, chain, fields...)
            }
        }
    }
}
```

This reuses the existing `containsComment()` helper (`iptables_linux.go:1478`)
but searches for `NETMAKER-LOCAL-ACL` instead of `NETMAKER`. Server rules
(`--comment NETMAKER`) are untouched. The pattern of listing rules then deleting
by parsed fields matches `clearNetmakerRules()` and `removeJumpRules()` — it's
established practice in this codebase.

#### `buildLocalACLRule` — rule construction (`iptables_linux.go:296-310`)

```go
func (i *iptablesManager) buildLocalACLRule(ifaceName string, rule LocalACLRule) []string {
    ruleSpec := []string{"-i", ifaceName, "-s", rule.Source}
    if rule.Protocol != "" {
        ruleSpec = append(ruleSpec, "-p", rule.Protocol)
    }
    if rule.Port != "" {
        // ... port range normalization (- → :) ...
        ruleSpec = append(ruleSpec, "--dport", rule.Port)
    }
    ruleSpec = append(ruleSpec, "-m", "comment", "--comment", localACLComment)
    ruleSpec = append(ruleSpec, "-j", "ACCEPT")
    return ruleSpec
}
```

The rule structure mirrors what netclient already generates for server ACL rules
(`AddAclRules`, `iptables_linux.go:742-897`): source match, optional protocol,
optional port, comment tag, action. The key difference is the comment — our
distinct `NETMAKER-LOCAL-ACL` tag.

Port range normalization (`8000-9000` → `8000:9000`) follows the same pattern
used throughout the codebase (e.g., `iptables_linux.go:640`, `iptables_linux.go:785`).

#### `insertLocalACLBeforeDrop` — position calculation (`iptables_linux.go:313-328`)

```go
func (i *iptablesManager) insertLocalACLBeforeDrop(client *iptables.IPTables, chain string, ruleSpec []string) {
    rules, err := client.List(defaultIpTable, chain)
    // ...
    pos := len(rules) - 1  // last rule position (1-based), which is the DROP
    if pos < 1 { pos = 1 }
    err = client.Insert(defaultIpTable, chain, pos, ruleSpec...)
}
```

The `iptables.List()` returns a header line plus one line per rule. `len(rules)-1`
gives the position of the last rule (the DROP). Inserting at that position pushes
the DROP down by one. This matches the approach used by `InsertIngressRoutingRules`
(`iptables_linux.go:579`) which calls `getLastRuleCnt()` for the same purpose.

### 4.5 Stubs: nftables and non-Linux

**`firewall/nftables_linux.go`** — logs a warning:
```go
func (n *nftablesManager) ApplyLocalACLRules(cfg *LocalACLConfig) {
    slog.Warn("44mesh: local ACL rules not yet implemented for nftables backend")
}
```

**`firewall/firewall_nonlinux.go`** — no-op:
```go
func (unimplementedFirewall) ApplyLocalACLRules(cfg *LocalACLConfig) {}
```

These satisfy the interface contract. The nftables implementation can be added
when the need arises — currently, all 44mesh deployments use iptables.

---

## 5. Why This Can't Be Done Server-Side

An obvious question: why not configure per-port ACLs on the Netmaker server
instead of adding client-side overrides?

Three reasons:

**5.1 The server doesn't know what services run on each node.** Netmaker manages
mesh connectivity. It knows which nodes should be able to reach which other
nodes. It does not know that Node A runs SSH on port 22, Node B runs a web
server on port 80, and Node C runs nothing but a monitoring agent on port 9100.
Service-level firewall policy is a node-local concern.

**5.2 AllowAll is the right mesh-level policy.** In 44mesh, every node should be
able to reach every other node — they're all part of the same community network
and they all need to route traffic between them. The server-side ACL model
(allow/deny between specific node pairs) doesn't express "allow mesh traffic but
restrict which ports are open on the host." It's a Layer 3 allow/deny; we need
Layer 4 filtering.

**5.3 The operator must have the final word.** In community networks, the
person maintaining a node at a rural site with no paved road and sporadic
connectivity needs to be able to harden that node's firewall locally, right now,
without coordinating with a central server that may be on another continent. The
config file can be deployed via Ansible, baked into an OS image, or edited with
`vi` over a serial console. It must survive server syncs.

---

## 6. Why This Is Safe for Upstream

### No behavioral change without opt-in

The entire feature is gated behind:
```go
// firewall/acl.go:18
if fwUpdate.AllowAll && localACL != nil && localACL.Enabled && len(localACL.Rules) > 0 {
```

Without the file on disk, `LoadLocalACLConfig()` returns `nil`, and execution
falls through to the original `ChangeACLInTarget(targetAccept)` path. Existing
Netmaker deployments — where `/etc/netclient/local-acl.json` doesn't exist —
behave identically to before.

### Clean separation of concerns

Local ACL rules use `--comment NETMAKER-LOCAL-ACL`. Server ACL rules use
`--comment NETMAKER`. The cleanup function (`removeLocalACLRules`) only touches
rules with the local comment. Server rules are never modified by this code path.

### Idempotent re-application

Every sync cycle: remove all local rules → set DROP → re-insert from config.
There's no accumulated state drift. The chain always converges to the config
file's contents.

### No new dependencies

The patch uses only `encoding/json`, `os`, `path/filepath`, and existing
codebase imports (`config`, `ncutils`, `slog`, `iptables`). No new Go modules.

### Minimal diff surface

| File | Lines changed |
|------|--------------|
| `firewall/local_acl.go` | +49 (new file) |
| `firewall/acl.go` | +7 |
| `firewall/firewall.go` | +2 |
| `firewall/iptables_linux.go` | +104 |
| `firewall/nftables_linux.go` | +5 |
| `firewall/firewall_nonlinux.go` | +1 |
| **Total** | **+168 lines** |

---

## 7. Relationship to the Policy Routing Patch

This local ACL patch is the firewall companion to the source-based policy
routing added in commit `ff2ec0bf`. Together they solve two halves of the
public-IP-via-VPN problem:

| Layer | Problem | Solution | Commit |
|-------|---------|----------|--------|
| Routing | `0.0.0.0/0` egress overwrites default route, breaks local connectivity | Source-based policy routing: only traffic from VPN IP goes through tunnel | `ff2ec0bf` |
| Routing | Single-node deployments skip policy routing setup | Fix IP/GwIP assignment in single-node path | `c113eb97` |
| Firewall | `AllowAll=true` exposes all host ports to public internet via tunnel | Local ACL config: explicit allowlist + default DROP | this patch |

Without policy routing, traffic wouldn't flow correctly. Without the local ACL,
traffic flows correctly but every service is exposed. Both are needed for a
production deployment of public IPs via Netmaker.

---

## 8. The Broader Case: Netmaker at the IXP Edge

This work demonstrates a use case for Netmaker that goes beyond the typical
"connect my cloud VMs" or "bridge my office LANs" deployments:

**Netmaker as a BGP-integrated IP distribution fabric.**

The border router peers with the IXP via BGP, announces a public prefix, and
uses Netmaker's egress gateway feature to route that prefix into the mesh. Each
node gets a public IP address that is reachable from anywhere on the internet.
WireGuard provides the encrypted transport. Netmaker provides the control plane
(peer management, key distribution, route propagation).

This is structurally similar to what Cloudflare WARP or Tailscale exit nodes do,
but with key differences:

- **Self-hosted and federated.** No vendor lock-in. The community owns the
  infrastructure.
- **Real public IPs, not NAT.** Each node gets a globally routable address, not
  a CGNAT or tunneled-only address. This matters for running servers, not just
  clients.
- **IXP-native.** Traffic enters and exits at the exchange point, benefiting
  from the low-latency, high-bandwidth interconnection that IXPs provide.

For the Netmaker team, this represents a new deployment category that validates
the architecture's flexibility. The egress gateway + WireGuard cryptokey routing
already handles the data plane correctly. The only gaps were in the client:
routing (solved by policy routing) and security (solved by local ACL). Both are
small, non-invasive patches that work alongside the existing server-managed ACL
system rather than replacing it.

---

## 9. Verification Procedures

### Build

```bash
cd /path/to/netclient
go build ./...
```

### Deploy and test

```bash
# 1. Create the config file on a node
cat > /etc/netclient/local-acl.json << 'EOF'
{
    "enabled": true,
    "log_dropped": true,
    "log_prefix": "NETMAKER-ACL-DROP: ",
    "rules": [
        {"source": "138.255.89.0/24", "protocol": "icmp", "port": "",   "comment": "ping from mesh"},
        {"source": "138.255.89.0/24", "protocol": "tcp",  "port": "80", "comment": "HTTP from mesh"},
        {"source": "138.255.89.0/24", "protocol": "udp",  "port": "53", "comment": "DNS from mesh"}
    ]
}
EOF

# 2. Restart netclient (or wait for next sync)
systemctl restart netclient

# 3. Verify chain state
sudo iptables -L NETMAKER-ACL-IN -v -n --line-numbers
# Expected: local ACCEPT rules with NETMAKER-LOCAL-ACL comment, LOG, then DROP

# 4. Verify drops are logged
sudo dmesg | grep "NETMAKER-ACL-DROP"

# 5. Test: SSH should be blocked from mesh
ssh -o ConnectTimeout=5 138.255.89.1     # should timeout

# 6. Test: HTTP should work
curl http://138.255.89.1                  # should connect

# 7. Disable and verify original behavior returns
# Edit local-acl.json: set "enabled": false
# Wait for sync or restart
sudo iptables -L NETMAKER-ACL-IN -v -n --line-numbers
# Expected: blanket ACCEPT rule, no NETMAKER-LOCAL-ACL rules

# 8. Remove file entirely
rm /etc/netclient/local-acl.json
# Wait for sync — blanket ACCEPT persists (original behavior)
```

---

## 10. Future Directions

- **nftables backend**: The current nftables stub logs a warning. A full
  implementation would translate `LocalACLRule` to nftables expressions,
  following the patterns in `nftables_linux.go`.

- **Server-side awareness**: A future Netmaker server version could expose a
  "local ACL template" that operators can push to nodes via the API, while still
  allowing node-local overrides.

- **Per-interface rules**: Currently rules match `-i netmaker`. For deployments
  with multiple Netmaker networks (multiple interfaces), the config could be
  extended to specify which interface each rule applies to.

- **Integration with Netmaker's ACL model**: If the Netmaker server gains
  support for per-port ACLs at the network level (not just node-pair allow/deny),
  the local ACL feature could serve as a fallback or merge strategy.
