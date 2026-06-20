# Project Environment Setup

This guide documents the base VMware environment for the SOC Detection Response Project.

## VMware Networks

| Network | Type | Purpose |
|---|---|---|
| VMnet8 | NAT | Internet access for Ubuntu servers during setup |
| VMnet2 | Host-only / project network | Isolated SOC project network |

Recommended VMnet2 settings:

```text
Subnet: 10.10.10.0
Mask: 255.255.255.0
DHCP: Disabled
```

## Virtual Machines

| VM | OS | CPU | RAM | Disk | Network Adapters |
|---|---|---:|---:|---:|---|
| `wazuh-server` | Ubuntu Server | 4 cores | 8-12 GB | 100 GB | VMnet8 + VMnet2 |
| `network-sensor` | Ubuntu Server | 2 cores | 4 GB | 50-60 GB | VMnet8 + VMnet2 |
| `win-endpoint` | Windows 11 | 2 cores | 4-6 GB | 80 GB | VMnet2 only after tool download |

## Project IP Plan

| VM | Interface | IP |
|---|---|---|
| `wazuh-server` | VMnet8 | DHCP |
| `wazuh-server` | VMnet2 | `10.10.10.10/24` |
| `network-sensor` | VMnet8 | DHCP |
| `network-sensor` | VMnet2 | `10.10.10.1/24` |
| `win-endpoint` | VMnet2 | `10.10.10.20/24` |

Windows Endpoint default gateway:

```text
10.10.10.1
```

## Current Verification Commands

On `wazuh-server`:

```bash
ip -br a
ip route
ping -c 4 8.8.8.8
ping -c 4 google.com
ping -c 4 10.10.10.1
```

On `network-sensor`:

```bash
ip -br a
ip route
ping -c 4 8.8.8.8
ping -c 4 google.com
ping -c 4 10.10.10.10
```

On `win-endpoint`:

```powershell
hostname
ipconfig /all
ping 10.10.10.1
ping 10.10.10.10
```

## Snapshot Milestones

Recommended VMware snapshots:

| Snapshot | When |
|---|---|
| `ubuntu-static-ip-verified` | After both Ubuntu servers have correct static project IPs |
| `windows-tools-installed` | After Sysmon, Atomic Red Team, and Wazuh Agent are installed |
| `three-vms-network-verified` | After Windows is moved to VMnet2 and can reach both Ubuntu servers |
| `before-security-tools` | Before Wazuh and Suricata deployment work |
