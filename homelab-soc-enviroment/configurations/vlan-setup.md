# VLAN Configuration

This document describes the VLAN setup on the TP-Link TL-SG105E managed switch.

## VLAN Overview

| VLAN ID | Name | Subnet | Purpose |
|---------|------|--------|---------|
| 10 | Users | 10.10.10.0/24 | Personal devices, isolated network |
| 20 | Servers | 192.168.10.0/24 | Proxmox host and VMs |

## Switch Port Configuration

**Device:** TP-Link TL-SG105E (5-Port Gigabit Easy Smart Switch)

| Port | VLAN 10 (Users) | VLAN 20 (Servers) | Connected Device |
|------|-----------------|-------------------|------------------|
| 1 | Tagged | Tagged | pfSense LAN (Trunk) |
| 2 | Untagged | - | User device |
| 3 | Untagged | - | User device |
| 4 | Tagged | Tagged | Proxmox Server (Trunk) |
| 5 | - | Untagged | Server network access |

## Port Roles Explained

### Port 1 — Firewall Trunk
- **Mode:** 802.1Q Trunk (all VLANs tagged)
- **Purpose:** Connects to pfSense LAN interface
- **Why Tagged:** pfSense handles inter-VLAN routing and needs to see VLAN tags to apply firewall rules per VLAN

### Ports 2 & 3 — User Access Ports
- **Mode:** Access (VLAN 10 untagged)
- **Purpose:** End-user devices (laptops, phones)
- **Security:** Isolated from Servers VLAN at firewall level

### Port 4 — Proxmox Trunk
- **Mode:** 802.1Q Trunk
- **Purpose:** Allows Proxmox VMs to be assigned to different VLANs
- **Use Case:** Future flexibility for VM network segmentation

### Port 5 — Server Access
- **Mode:** Access (VLAN 20 untagged)
- **Purpose:** Direct server network access
- **Note:** Configuration may change as lab expands

## pfSense VLAN Interfaces

On the pfSense side, the following VLAN interfaces are configured on the LAN parent interface:

| Interface | VLAN ID | IP Address | Role |
|-----------|---------|------------|------|
| LAN | - | (Parent interface) | Trunk to switch |
| VLAN10 | 10 | 10.10.10.1/24 | Users gateway |
| VLAN20 | 20 | 192.168.10.1/24 | Servers gateway |

## Segmentation Benefits

1. **Isolation:** Compromised user device cannot directly access lab servers
2. **Visibility:** All inter-VLAN traffic passes through pfSense for inspection
3. **Control:** Granular firewall rules per VLAN
4. **Monitoring:** Zeek and Suricata see all routed traffic

## Future Considerations

- Add dedicated VLAN for IoT devices
- Create isolated VLAN for malware analysis (no internet access)
- Implement VLAN for management traffic (switch, Proxmox UI)
