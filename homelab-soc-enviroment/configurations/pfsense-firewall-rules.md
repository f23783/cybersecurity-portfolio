# Firewall Rules Philosophy

This document describes the security philosophy and general approach to firewall rules in this lab environment. Specific rules are intentionally omitted for security reasons.

> ⚠️ **Security Note:** Detailed firewall configurations are not published to avoid exposing network architecture specifics. This document focuses on the *approach* rather than implementation details.

## Core Principles

### 1. Default Deny
All traffic is denied by default. Rules explicitly allow only necessary traffic.

```
Default policy: BLOCK ALL
Exceptions: Explicitly defined allow rules
```

### 2. Least Privilege
Each VLAN only has access to resources it absolutely needs.

### 3. Defense in Depth
Multiple layers of security — network segmentation is just one layer.

## Inter-VLAN Policy

| Source | Destination | Policy | Rationale |
|--------|-------------|--------|-----------|
| Users | Servers | **Deny** | User devices should not access lab infrastructure |
| Servers | Users | **Deny** | Lab VMs should not reach personal devices |
| Users | Internet | Allow | Normal browsing |
| Servers | Internet | Allow (selective) | Updates, threat intel feeds |

## Rule Design Approach

### Explicit Over Implicit
Every allow rule has a documented reason. If you can't explain why a rule exists, it probably shouldn't.

### Log Everything
All blocked traffic is logged for analysis. Allowed traffic on sensitive ports is also logged.

### Regular Review
Firewall rules are reviewed periodically to remove unused rules and verify necessity.

## Monitoring Integration

Firewall logs are forwarded to Splunk for:
- Blocked connection analysis
- Anomaly detection
- Baseline traffic pattern establishment

## What's NOT Covered Here

For security reasons, this document does not include:
- Specific IP addresses or port numbers
- NAT and port forwarding rules
- Service-specific allow rules
- Management access rules

## Learning Resources

If you're building a similar setup, these resources helped me:

- [pfSense Documentation — Firewall Rules](https://docs.netgate.com/pfsense/en/latest/firewall/index.html)
- [VLAN Best Practices](https://docs.netgate.com/pfsense/en/latest/vlan/index.html)
- Lawrence Systems YouTube channel — Excellent pfSense tutorials
