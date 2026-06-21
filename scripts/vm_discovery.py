#!/usr/bin/env python3
"""Discover Proxmox VMs and assemble a complete picture from many signals.

Source of truth is Proxmox, reached by **root SSH** to a hypervisor in each
cluster (no API tokens exist) running `pvesh`/`cat` on the cluster filesystem.
This is the read-only discovery half — it does NOT write to NetBox. It mirrors
the conventions of the sibling `scripts/discovery.py` (CustomFormatter logger,
argparse with granular flags, shelling out to `ssh`).

Signals gathered:
  Proxmox /cluster/resources  -> vmid, name, node, cluster, status, type
  pmxcfs .conf (cluster-wide) -> NICs (MAC/bridge/VLAN), vCPU, memory, disk,
                                 ostype, Proxmox tags, description, cloud-init IPs
  qemu-guest-agent (running)  -> runtime IPs, guest hostname, OS info
  SSH into VM (--ssh-enrich)  -> canonical FQDN, default-route source IP, OS,
                                 running services, listening ports
  local DNS (always)          -> PTR of mgmt IP, forward-resolve canonical FQDN
  NetBox (--netbox)           -> does a VM/IP already exist (read-only)
  Ansible inventory (--inventory PATH) -> cross-reference against managed hosts

Examples:
  ./vm_discovery.py --list-vms --jump shell.sfmix.org
  ./vm_discovery.py --list-vms --ssh-enrich --netbox \\
      --inventory ../ansible/inventory/servers.yml --jump shell.sfmix.org
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


# ── Logging (mirrors discovery.py) ────────────────────────────────────

class CustomFormatter(logging.Formatter):
    whiteblack = "\x1b[37;40m"
    yellow = "\x1b[33;40m"
    red = "\x1b[31;40m"
    bold_red = "\x1b[31;101m"
    reset = "\x1b[0m"
    message_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    FORMATS = {
        logging.DEBUG: whiteblack + message_format + reset,
        logging.INFO: whiteblack + message_format + reset,
        logging.WARNING: yellow + message_format + reset,
        logging.ERROR: red + message_format + reset,
        logging.CRITICAL: bold_red + message_format + reset,
    }

    def format(self, record):
        if not sys.stderr.isatty():
            return logging.Formatter(self.message_format).format(record)
        return logging.Formatter(self.FORMATS.get(record.levelno)).format(record)


logger = logging.getLogger("vm_discovery")
logger.setLevel(logging.DEBUG)
_ch = logging.StreamHandler()
_ch.setFormatter(CustomFormatter())
logger.addHandler(_ch)


# ── Config ────────────────────────────────────────────────────────────

# One SSH entrypoint hypervisor per Proxmox cluster (canonical site code -> a
# cluster member). `pvesh get /cluster/resources` from one member returns VMs
# across all nodes in that cluster.
PROXMOX_CLUSTERS: Dict[str, str] = {
    "sfo02": "pve01-paulave200-sfo.sfmix.org",
    "fmt01": "pve01-warmspringsblvd48233-fmt.sfmix.org",
    "scl04": "pve01.scl04.sfmix.org",
}

DOMAIN = "sfmix.org"

_SKIP_IP_PREFIXES = ("127.", "::1", "fe80:", "169.254.")
_NONMGMT_IFACE_PREFIXES = ("docker", "br-", "veth", "tailscale", "wg")
_NIC_MODELS = ("virtio", "e1000e", "e1000", "vmxnet3", "rtl8139")
def _pick_mgmt_v4(addrs: "List[VMAddr]") -> Optional[str]:
    """First plausible mgmt IPv4 from a list (skip loopback/docker/overlay ifaces)."""
    for a in addrs:
        if ":" in a.ip or a.ip.startswith(_SKIP_IP_PREFIXES) or a.ip.startswith("172.17."):
            continue
        if a.ifname and a.ifname.startswith(_NONMGMT_IFACE_PREFIXES):
            continue
        return a.ip
    return None


_OSTYPE_PLATFORM = {
    "l26": "linux", "l24": "linux",
    "win10": "windows", "win11": "windows", "win8": "windows",
    "win7": "windows", "w2k": "windows", "wxp": "windows",
    "solaris": "solaris", "other": "other",
}


# ── SSH helper ────────────────────────────────────────────────────────

def _ssh_base(jump: Optional[str]) -> List[str]:
    cmd = ["ssh", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=12"]
    if jump:
        cmd += ["-J", jump]
    return cmd


def ssh_run(host: str, remote_cmd: str, jump: Optional[str] = None,
            user: Optional[str] = None, port: Optional[int] = None,
            timeout: int = 60) -> str:
    target = f"{user}@{host}" if user else host
    cmd = _ssh_base(jump)
    if port:
        cmd += ["-p", str(port)]
    full = cmd + [target, remote_cmd]
    result = subprocess.run(full, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        err = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(
            f"ssh {target}{':' + str(port) if port else ''} "
            f"failed (rc={result.returncode}): {err or '(no stderr)'}")
    return result.stdout.decode("utf-8", "replace")


# ── Data model ────────────────────────────────────────────────────────

@dataclass
class VMNic:
    key: str
    model: str
    mac: str
    bridge: Optional[str] = None
    vlan: Optional[int] = None


@dataclass
class VMAddr:
    ip: str
    prefix: int
    mac: Optional[str] = None
    ifname: Optional[str] = None


@dataclass
class VM:
    vmid: int
    name: str
    node: str
    cluster: str
    status: str
    vmtype: str
    # pmxcfs config:
    nics: List[VMNic] = field(default_factory=list)
    vcpus: Optional[int] = None
    memory_mb: Optional[int] = None
    disk_gb: Optional[float] = None
    ostype: Optional[str] = None
    prox_tags: List[str] = field(default_factory=list)
    description: Optional[str] = None
    agent_enabled: bool = False
    cloudinit_ips: List[str] = field(default_factory=list)
    # guest agent:
    agent_addrs: List[VMAddr] = field(default_factory=list)
    agent_ifnames: Dict[str, str] = field(default_factory=dict)  # MAC -> guest ifname
    agent_hostname: Optional[str] = None
    agent_os: Optional[str] = None
    # SSH enrichment (ground truth for names/IPs/identity when reachable):
    ssh_fqdn: Optional[str] = None
    ssh_source_ip: Optional[str] = None
    ssh_os: Optional[str] = None
    ssh_addrs: List[VMAddr] = field(default_factory=list)
    ssh_mac_ifname: Dict[str, str] = field(default_factory=dict)  # MAC -> ifname
    ssh_services: List[str] = field(default_factory=list)
    ssh_listen_ports: List[str] = field(default_factory=list)
    ssh_target: Optional[str] = None   # how we logged in (host:port)
    ssh_error: Optional[str] = None

    @property
    def identity_verified(self) -> bool:
        """True only if the guest confirmed its own hostname (SSH or agent).
        Proxmox VM names are decorative and never authoritative."""
        return bool(self.ssh_fqdn or self.agent_hostname)

    @property
    def data_source(self) -> str:
        if self.ssh_addrs:
            return "ssh"
        if self.agent_addrs:
            return "agent"
        return "proxmox-config"

    def addrs_for_mac(self, mac: str) -> List[VMAddr]:
        """IPs for a vNIC MAC: SSH ground truth preferred, else guest agent."""
        ssh = [a for a in self.ssh_addrs if a.mac == mac]
        return ssh if ssh else [a for a in self.agent_addrs if a.mac == mac]

    def ifname_for_mac(self, mac: str) -> Optional[str]:
        """Guest interface name for a vNIC MAC: SSH preferred, else agent."""
        return self.ssh_mac_ifname.get(mac) or self.agent_ifnames.get(mac)
    # DNS cross-check:
    mgmt_ptr: Optional[str] = None
    fqdn_dns_ips: List[str] = field(default_factory=list)
    # external cross-references:
    in_netbox: Optional[bool] = None
    in_inventory: Optional[bool] = None

    @property
    def platform(self) -> Optional[str]:
        if self.ssh_os:
            return self.ssh_os
        if self.agent_os:
            return self.agent_os
        if self.ostype:
            return _OSTYPE_PLATFORM.get(self.ostype, self.ostype)
        return None

    @property
    def canonical_fqdn(self) -> str:
        """Best canonical FQDN: SSH hostname -f > guest-agent hostname > name.

        Append DOMAIN unless the value is already in it. Note guest hostnames may
        be multi-label but not fully qualified (e.g. 'netbox.sfo02'), so a mere
        dot is not enough to treat a value as an FQDN.
        """
        for cand in (self.ssh_fqdn, self.agent_hostname, self.name):
            if cand:
                base = cand
                break
        else:
            base = self.name
        if base == DOMAIN or base.endswith("." + DOMAIN):
            return base
        return f"{base}.{DOMAIN}"

    @property
    def mgmt_ip(self) -> Optional[str]:
        """Source IP a log line would carry: SSH prefsrc > SSH addr > agent addr."""
        return (self.ssh_source_ip or _pick_mgmt_v4(self.ssh_addrs)
                or _pick_mgmt_v4(self.agent_addrs))


# ── Proxmox config parsing ────────────────────────────────────────────

def _parse_net_line(key: str, value: str) -> Optional[VMNic]:
    model = mac = bridge = None
    vlan = None
    for part in value.split(","):
        if "=" not in part:
            continue
        k, v = (s.strip() for s in part.split("=", 1))
        if k in _NIC_MODELS:
            model, mac = k, v
        elif k == "macaddr":
            mac = v
        elif k == "bridge":
            bridge = v
        elif k == "tag":
            try:
                vlan = int(v)
            except ValueError:
                pass
    if not mac:
        return None
    return VMNic(key, model or "virtio", mac.upper(), bridge, vlan)


_SIZE_RE = re.compile(r"size=(\d+(?:\.\d+)?)([KMGT])", re.IGNORECASE)
_DISK_KEY_RE = re.compile(r"^(scsi|virtio|sata|ide)\d+$")
_SIZE_UNIT_GB = {"K": 1 / 1024 / 1024, "M": 1 / 1024, "G": 1.0, "T": 1024.0}


def _parse_config(vm: VM, text: str) -> None:
    cores = sockets = None
    for line in text.splitlines():
        if line.startswith("["):
            break  # snapshot/pending section
        k, sep, v = line.partition(":")
        if not sep:
            continue
        k, v = k.strip(), v.strip()
        if k.startswith("net") and k[3:].isdigit():
            nic = _parse_net_line(k, v)
            if nic:
                vm.nics.append(nic)
        elif _DISK_KEY_RE.match(k):
            if "media=cdrom" in v:        # mounted ISO, not a disk
                continue
            m = _SIZE_RE.search(v)
            if m:
                gb = float(m.group(1)) * _SIZE_UNIT_GB[m.group(2).upper()]
                vm.disk_gb = round((vm.disk_gb or 0) + gb, 1)
        elif k == "cores":
            cores = int(v) if v.isdigit() else None
        elif k == "sockets":
            sockets = int(v) if v.isdigit() else None
        elif k == "memory":
            vm.memory_mb = int(v) if v.isdigit() else None
        elif k == "ostype":
            vm.ostype = v
        elif k == "agent":
            vm.agent_enabled = v.split(",")[0] in ("1", "enabled=1")
        elif k == "tags":
            vm.prox_tags = [t for t in re.split(r"[;,]", v) if t]
        elif k == "description":
            vm.description = v
        elif k.startswith("ipconfig") and "ip=" in v:
            for part in v.split(","):
                if part.strip().startswith("ip=") and part.strip() != "ip=dhcp":
                    vm.cloudinit_ips.append(part.split("=", 1)[1])
    if cores:
        vm.vcpus = cores * (sockets or 1)


def _parse_agent_interfaces(payload: object) -> List[VMAddr]:
    ifaces = payload.get("result") if isinstance(payload, dict) else payload
    out: List[VMAddr] = []
    if not isinstance(ifaces, list):
        return out
    for iface in ifaces:
        name, mac = iface.get("name"), iface.get("hardware-address")
        if name == "lo":
            continue
        for addr in iface.get("ip-addresses", []) or []:
            ip = addr.get("ip-address", "")
            if not ip or ip.startswith(_SKIP_IP_PREFIXES):
                continue
            out.append(VMAddr(ip, int(addr.get("prefix", 0)),
                              (mac or "").upper() or None, name))
    return out


def _parse_agent_ifnames(payload: object) -> Dict[str, str]:
    """MAC -> guest interface name for every guest NIC (incl. IP-less ones)."""
    ifaces = payload.get("result") if isinstance(payload, dict) else payload
    out: Dict[str, str] = {}
    if not isinstance(ifaces, list):
        return out
    for iface in ifaces:
        name = iface.get("name")
        mac = (iface.get("hardware-address") or "").upper()
        if name and name != "lo" and mac:
            out[mac] = name
    return out


# ── Bulk remote fetch ─────────────────────────────────────────────────

_REC, _FLD = "@@@VMREC@@@", "@@@FLD@@@"


def _bulk_script(vms_meta: List[tuple]) -> str:
    """Emit config (+ agent net/hostname/os for running VMs) for every VM once.

    Configs come straight from pmxcfs (cluster-wide, fast); the slow agent calls
    run only for running VMs, each time-boxed.
    """
    lines = ["set -u"]
    for vmid, node, running in vms_meta:
        lines.append(f'printf "%s\\n" "{_REC}{vmid}"')
        lines.append(f'printf "%s\\n" "{_FLD}config"; '
                     f'cat /etc/pve/nodes/{node}/qemu-server/{vmid}.conf 2>/dev/null')
        if running:
            for cmd in ("network-get-interfaces", "get-host-name", "get-osinfo"):
                lines.append(
                    f'printf "\\n%s\\n" "{_FLD}{cmd}"; '
                    f'timeout 8 pvesh get /nodes/{node}/qemu/{vmid}/agent/{cmd} '
                    f'--output-format json 2>/dev/null || true')
    return "\n".join(lines)


def _apply_bulk(vms: Dict[int, VM], bulk: str) -> None:
    cur: Optional[VM] = None
    fld: Optional[str] = None
    buf: List[str] = []

    def flush():
        if cur is None or fld is None:
            return
        text = "\n".join(buf).strip()
        if not text:
            return
        if fld == "config":
            _parse_config(cur, text)
            return
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        if fld == "network-get-interfaces":
            cur.agent_addrs.extend(_parse_agent_interfaces(data))
            cur.agent_ifnames.update(_parse_agent_ifnames(data))
        elif fld == "get-host-name":
            res = data.get("result", data) if isinstance(data, dict) else {}
            cur.agent_hostname = (res or {}).get("host-name")
        elif fld == "get-osinfo":
            res = data.get("result", data) if isinstance(data, dict) else {}
            cur.agent_os = (res or {}).get("pretty-name") or (res or {}).get("name")

    for line in bulk.splitlines():
        if line.startswith(_REC):
            flush(); buf = []; fld = None
            cur = vms.get(int(line[len(_REC):]))
        elif line.startswith(_FLD):
            flush(); buf = []
            fld = line[len(_FLD):]
        else:
            buf.append(line)
    flush()


def enumerate_cluster_vms(cluster: str, entrypoint: str, jump: Optional[str],
                          name_filter: Optional[List[str]]) -> List[VM]:
    logger.info(f"Enumerating VMs in cluster {cluster} (via {entrypoint})")
    resources = json.loads(ssh_run(
        entrypoint,
        "pvesh get /cluster/resources --type vm --output-format json",
        jump=jump, user="root"))

    vms: Dict[int, VM] = {}
    for r in resources:
        if r.get("type") != "qemu":   # LXC: a later phase
            continue
        name = r.get("name", "")
        if name_filter and not any(f in name for f in name_filter):
            continue
        vmid = int(r["vmid"])
        vms[vmid] = VM(vmid, name, r.get("node", ""), cluster,
                       r.get("status", ""), r.get("type", "qemu"))
    if not vms:
        return []
    meta = [(v.vmid, v.node, v.status == "running") for v in vms.values()]
    _apply_bulk(vms, ssh_run(entrypoint, _bulk_script(meta), jump=jump,
                             user="root", timeout=240))
    return list(vms.values())


# ── SSH enrichment ────────────────────────────────────────────────────

# Ground-truth gather from the guest. `ip -j addr` is the authoritative interface
# + IP list; `ip route get` gives the real source IP; rest is identity/context.
_ENRICH_CMD = (
    # `hostname -f` is Linux; OpenBSD has no -f but plain `hostname` is the FQDN.
    "hostname -f 2>/dev/null || hostname 2>/dev/null; echo @@OS@@; "
    # NOT `. /etc/os-release` — sourcing a missing file kills a non-interactive
    # OpenBSD shell. grep is safe; uname is the BSD fallback.
    "grep -h '^PRETTY_NAME=' /etc/os-release 2>/dev/null | head -1; "
    "uname -sr 2>/dev/null; echo @@SRC@@; "
    "ip -j route get 1.1.1.1 2>/dev/null; echo @@ADDR@@; "
    "ip -j addr 2>/dev/null; echo @@SVC@@; "
    "systemctl list-units --type=service --state=running --no-legend "
    "--no-pager 2>/dev/null | awk '{print $1}'; echo @@PORTS@@; "
    "ss -tlnH 2>/dev/null | awk '{print $4}' | sort -u; echo @@IFCONFIG@@; "
    "ifconfig 2>/dev/null; true")   # `; true`: never let a missing tool
    # (e.g. ifconfig absent on net-tools-less Ubuntu) make the whole cmd exit
    # non-zero and discard the data we already gathered. BSD fallback for OpenBSD.


def _clean_ssh_error(msg: str) -> str:
    """Pull the meaningful line out of ssh stderr (drop banners/host-key noise)."""
    noise = ("Warning: Permanently added", "WARNING", "REMOTE HOST", "@@@@",
             "IT IS POSSIBLE", "Someone could", "It is also possible",
             "host key has just been", "offending key", "add correct host key",
             "Host key for", "Please contact", "DNS SPOOFING")
    lines = [ln.strip() for ln in msg.splitlines() if ln.strip()]
    cand = [ln for ln in lines
            if not any(n in ln for n in noise) and set(ln) - set("@ ")]
    return (cand[-1] if cand else (lines[-1] if lines else msg))[:100]


def _parse_ip_addr_json(text: str):
    """Parse `ip -j addr` into (addrs, mac->ifname). Skips lo and link-local."""
    addrs: List[VMAddr] = []
    mac_ifname: Dict[str, str] = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return addrs, mac_ifname
    for iface in data if isinstance(data, list) else []:
        name = iface.get("ifname")
        mac = (iface.get("address") or "").upper()
        if not name or name == "lo":
            continue
        if mac:
            mac_ifname[mac] = name
        for ai in iface.get("addr_info", []) or []:
            ip = ai.get("local")
            if not ip or ip.startswith(_SKIP_IP_PREFIXES):
                continue
            addrs.append(VMAddr(ip, int(ai.get("prefixlen", 0)),
                                mac or None, name))
    return addrs, mac_ifname


def _parse_ifconfig(text: str):
    """Parse BSD `ifconfig` (OpenBSD/FreeBSD) into (addrs, mac->ifname)."""
    addrs: List[VMAddr] = []
    mac_ifname: Dict[str, str] = {}
    name: Optional[str] = None
    mac: Optional[str] = None
    for line in text.splitlines():
        if line and not line[0].isspace():       # "em0: flags=8843<UP,...>"
            name = line.split(":", 1)[0]
            mac = None
            continue
        if not name or name.startswith("lo"):
            continue
        s = line.strip()
        if s.startswith("lladdr "):
            mac = s.split()[1].upper()
            mac_ifname[mac] = name
        elif s.startswith("inet ") and "netmask" in s:
            parts = s.split()
            ip = parts[1]
            try:
                prefix = bin(int(parts[parts.index("netmask") + 1], 16)).count("1")
            except (ValueError, IndexError):
                prefix = 0
            if not ip.startswith(_SKIP_IP_PREFIXES):
                addrs.append(VMAddr(ip, prefix, mac, name))
        elif s.startswith("inet6 ") and "prefixlen" in s:
            parts = s.split()
            ip = parts[1].split("%")[0]
            try:
                prefix = int(parts[parts.index("prefixlen") + 1])
            except (ValueError, IndexError):
                prefix = 0
            if not ip.startswith(_SKIP_IP_PREFIXES):
                addrs.append(VMAddr(ip, prefix, mac, name))
    return addrs, mac_ifname


def _apply_enrich_output(vm: VM, out: str) -> None:
    fqdn, _, rest = out.partition("@@OS@@")
    os_pretty, _, rest = rest.partition("@@SRC@@")
    route_json, _, rest = rest.partition("@@ADDR@@")
    addr_json, _, rest = rest.partition("@@SVC@@")
    svc, _, rest = rest.partition("@@PORTS@@")
    ports, _, ifc = rest.partition("@@IFCONFIG@@")
    if fqdn.strip():
        vm.ssh_fqdn = fqdn.strip().splitlines()[-1]
    os_lines = [ln.strip() for ln in os_pretty.strip().splitlines() if ln.strip()]
    pretty = next((ln.split("=", 1)[1].strip().strip('"')
                   for ln in os_lines if ln.startswith("PRETTY_NAME=")), None)
    vm.ssh_os = pretty or (os_lines[-1] if os_lines else None)
    try:
        route = json.loads(route_json.strip())
        if isinstance(route, list) and route:
            vm.ssh_source_ip = route[0].get("prefsrc")
    except json.JSONDecodeError:
        pass
    addrs, macs = _parse_ip_addr_json(addr_json.strip())
    if not addrs and ifc.strip():          # OpenBSD/BSD path
        addrs, macs = _parse_ifconfig(ifc.strip())
    vm.ssh_addrs, vm.ssh_mac_ifname = addrs, macs
    vm.ssh_services = [s for s in svc.split() if s.endswith(".service")]
    vm.ssh_listen_ports = [p for p in ports.split() if p]


# Decorative-name suffixes to strip when guessing the real hostname.
_NAME_SUFFIXES = ("-production", "-prod", "-new", "-old", "-nostart",
                  "-distro", "-depricated", "-deprecated", "-test")
_SSH_PORTS = (22, 2222)


def _candidate_targets(vm: VM) -> List[str]:
    """SSH targets to try, best first. Proxmox names are decorative, so derive
    candidate hostnames from them (cleaned) plus mgmt.<name>, and any agent IP."""
    raw = vm.name.strip().lower().replace(" ", "")
    base = {raw}
    for suf in _NAME_SUFFIXES:
        if raw.endswith(suf):
            base.add(raw[: -len(suf)])
    # Proxmox names may use '.' where the real hostname uses '-' (e.g.
    # 'tailscale.sfo02' -> 'tailscale-sfo02'); try both, original form first.
    labels: List[str] = []
    for label in sorted(base, key=len):             # cleaned (shorter) first
        labels.append(label)
        if "." in label:
            labels.append(label.replace(".", "-"))
    names: List[str] = []
    for label in labels:
        names += [f"{label}.{DOMAIN}", f"mgmt.{label}.{DOMAIN}"]
    targets = ([vm.mgmt_ip] if vm.mgmt_ip else []) + names
    seen: Set[str] = set()
    return [t for t in targets if t and not (t in seen or seen.add(t))]


def _host_exists_err(msg: str) -> bool:
    """True if the SSH error implies the host is up (so a different port may work)."""
    return any(s in msg for s in ("refused", "Permission denied", "publickey",
                                  "Too many", "closed by", "denied"))


def ssh_enrich(vm: VM, jump: Optional[str], user: Optional[str] = None) -> None:
    """Gather ground truth over SSH. Tries derived hostnames and ports 22/2222."""
    last_err = "no reachable target"
    for target in _candidate_targets(vm):
        for i, port in enumerate(_SSH_PORTS):
            try:
                out = ssh_run(target, _ENRICH_CMD, jump=jump, user=user,
                              port=port, timeout=20)
            except Exception as e:  # noqa: BLE001 - best-effort
                last_err = _clean_ssh_error(str(e))
                # Only try the alt port if the host answered (e.g. refused on 22).
                if i == 0 and not _host_exists_err(last_err):
                    break
                continue
            _apply_enrich_output(vm, out)
            if vm.ssh_addrs or vm.ssh_fqdn:
                vm.ssh_error = None
                vm.ssh_target = f"{target}:{port}"
                return
    vm.ssh_error = last_err


# ── DNS cross-check (local resolver) ──────────────────────────────────

def dns_crosscheck(vm: VM) -> None:
    if vm.mgmt_ip:
        try:
            vm.mgmt_ptr = socket.gethostbyaddr(vm.mgmt_ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            vm.mgmt_ptr = None
    try:
        infos = socket.getaddrinfo(vm.canonical_fqdn, None)
        vm.fqdn_dns_ips = sorted({i[4][0] for i in infos})
    except (socket.gaierror, OSError):
        vm.fqdn_dns_ips = []


# ── External cross-references ──────────────────────────────────────────

def _load_dotenv(env_path: Optional[str]) -> None:
    if env_path and not os.path.exists(env_path):
        logger.warning(f"env file not found: {env_path}")
        return
    if not env_path:
        return
    for raw in open(env_path):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def get_netbox_api(env_path: Optional[str] = None):
    """Return a pynetbox API handle, or None if unavailable."""
    _load_dotenv(env_path)
    endpoint = os.environ.get("NETBOX_API_ENDPOINT")
    token = os.environ.get("NETBOX_API_TOKEN")
    if not (endpoint and token):
        logger.warning("NETBOX_API_ENDPOINT/TOKEN not set")
        return None
    try:
        import pynetbox  # noqa: PLC0415
    except ImportError:
        logger.warning("pynetbox not installed")
        return None
    return pynetbox.api(endpoint, token=token)


def load_netbox_names(env_path: Optional[str]) -> Optional[Set[str]]:
    """Return the set of existing NetBox VM names (read-only), or None on failure."""
    nb = get_netbox_api(env_path)
    if nb is None:
        return None
    try:
        return {vm.name for vm in nb.virtualization.virtual_machines.all()}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"NetBox query failed: {e}")
        return None


def load_inventory_hosts(path: Optional[str]) -> Optional[Set[str]]:
    """Return the set of Ansible inventory hostnames, or None on failure."""
    if not path:
        return None
    try:
        out = subprocess.check_output(
            ["ansible-inventory", "-i", path, "--list"], text=True,
            stderr=subprocess.DEVNULL)
        data = json.loads(out)
        hosts = set((data.get("_meta", {}).get("hostvars") or {}).keys())
        hosts.discard("localhost")
        return hosts
    except Exception as e:  # noqa: BLE001
        logger.warning(f"ansible-inventory failed ({e}); skipping inventory cross-ref")
        return None


# ── Report ────────────────────────────────────────────────────────────

def print_report(vms: List[VM], inventory: Optional[Set[str]]) -> None:
    vms = sorted(vms, key=lambda v: (v.cluster, v.name))
    for v in vms:
        src = ("ssh" if v.ssh_fqdn else "agent" if v.agent_hostname else "derived")
        flags = []
        if v.in_netbox is True:
            flags.append("in-netbox")
        elif v.in_netbox is False:
            flags.append("NOT-in-netbox")
        if v.in_inventory is True:
            flags.append("in-inventory")
        elif v.in_inventory is False:
            flags.append("NOT-in-inventory")
        print(f"\n[{v.cluster}] {v.name}  (vmid {v.vmid}, {v.status}, node {v.node})"
              f"{'  ' + ' '.join(flags) if flags else ''}")
        print(f"    fqdn:     {v.canonical_fqdn}  ({src})")
        specs = []
        if v.vcpus:
            specs.append(f"{v.vcpus} vCPU")
        if v.memory_mb:
            specs.append(f"{v.memory_mb} MB")
        if v.disk_gb:
            specs.append(f"{v.disk_gb:g} GB")
        if v.platform:
            specs.append(v.platform)
        if v.prox_tags:
            specs.append("tags=" + ",".join(v.prox_tags))
        if specs:
            print(f"    specs:    {', '.join(specs)}"
                  f"{'  agent' if v.agent_enabled else ''}")
        print(f"    mgmt ip:  {v.mgmt_ip or '-'}"
              + (f"   ptr={v.mgmt_ptr}" if v.mgmt_ptr else ""))
        if v.fqdn_dns_ips:
            match = v.mgmt_ip in v.fqdn_dns_ips if v.mgmt_ip else None
            note = "" if match is None else ("  ✓match" if match else "  ✗MISMATCH")
            print(f"    fqdn dns: {', '.join(v.fqdn_dns_ips)}{note}")
        elif v.status == "running":
            print(f"    fqdn dns: (does not resolve)")
        for nic in v.nics:
            vlan = f" vlan={nic.vlan}" if nic.vlan is not None else ""
            print(f"    nic {nic.key}: {nic.mac} bridge={nic.bridge}{vlan}")
        for a in v.agent_addrs:
            print(f"    ip  {a.ip}/{a.prefix} ({a.ifname})")
        if v.ssh_os:
            print(f"    os:       {v.ssh_os}")
        if v.ssh_services:
            notable = [s[:-8] for s in v.ssh_services
                       if not s.startswith(("systemd-", "dbus", "getty", "user@",
                                            "cron", "rsyslog", "ssh"))]
            print(f"    services: {len(v.ssh_services)} running"
                  + (f" — {', '.join(sorted(notable)[:10])}" if notable else ""))
        if v.ssh_listen_ports:
            print(f"    listen:   {len(v.ssh_listen_ports)} sockets")
        if v.ssh_error:
            print(f"    ssh-enrich failed: {v.ssh_error}")

    running = sum(1 for v in vms if v.status == "running")
    print(f"\n{len(vms)} VM(s): {running} running, {len(vms) - running} stopped.")

    # Identity gaps: Proxmox name doesn't match the host's own reported name.
    mism = [v for v in vms
            if (v.ssh_fqdn or v.agent_hostname)
            and (v.ssh_fqdn or v.agent_hostname) not in
                (v.name, f"{v.name}.{DOMAIN}")]
    if mism:
        print("\nProxmox name != host-reported name:")
        for v in mism:
            print(f"  {v.name}  ->  {v.ssh_fqdn or v.agent_hostname}")

    # Duplicate MACs (stale clones can share a MAC, e.g. an -old VM).
    mac_owners: Dict[str, Set[str]] = {}
    for v in vms:
        for nic in v.nics:
            mac_owners.setdefault(nic.mac, set()).add(v.name)
    dups = {m: o for m, o in mac_owners.items() if len(o) > 1}
    if dups:
        print("\nDuplicate MACs across VMs (stale clone / collision risk):")
        for m, owners in dups.items():
            print(f"  {m}: {', '.join(sorted(owners))}")

    if inventory is not None:
        discovered = {v.canonical_fqdn for v in vms}
        missing = sorted(inventory - discovered)
        if missing:
            print(f"\nInventory hosts NOT discovered as VMs [{len(missing)}] "
                  "(bare metal, appliances, or naming gaps):")
            for h in missing:
                print(f"  {h}")


# ── NetBox object preview (what a sync would create; no writes) ───────

_STALE_RE = re.compile(
    r"(donotstart|dont[-_]?start|nostart|[-_]old\b|old[-_]|depri?cated|"
    r"deprecated|\btest\b|template|^ubuntu\d)", re.I)


def is_stale(name: str) -> bool:
    return bool(_STALE_RE.search(name))


def netbox_preview(vms: List[VM], include_offline: bool = False) -> None:
    """Print the NetBox objects a sync would create for each VM (read-only).

    Skips stale-named VMs and (by default) offline ones — offline VMs are nearly
    all decommissioned. Pass include_offline=True to import them anyway.
    """
    vms = sorted(vms, key=lambda v: (v.cluster, v.name))
    would_sync = skipped = 0
    for v in vms:
        reason = None
        if is_stale(v.name):
            reason = "stale name"
        elif v.status != "running" and not include_offline:
            reason = "offline"
        if reason:
            skipped += 1
            print(f"\n# SKIP ({reason}): {v.name}  [{v.cluster}, {v.status}]")
            continue
        would_sync += 1
        status = "active" if v.status == "running" else "offline"
        print(f"\nVirtualMachine  {v.canonical_fqdn}")
        print(f"    cluster        = {v.cluster}")
        print(f"    status         = {status}   (proxmox: {v.status})")
        if v.identity_verified:
            print(f"    identity       = {v.canonical_fqdn}  "
                  f"(authoritative: {'ssh ' + (v.ssh_target or '') if v.ssh_fqdn else 'guest agent'})")
        else:
            print(f"    identity       = UNVERIFIED — no SSH/agent; name derived "
                  f"from decorative proxmox name {v.name!r}"
                  + (f"; ssh: {v.ssh_error}" if v.ssh_error else ""))
        print(f"    name(proxmox)  = {v.name}  (decorative)")
        if v.vcpus:
            print(f"    vcpus          = {v.vcpus}")
        if v.memory_mb:
            print(f"    memory (MB)    = {v.memory_mb}")
        if v.disk_gb:
            print(f"    disk (GB)      = {v.disk_gb:g}")
        if v.platform:
            print(f"    platform       = {v.platform}")
        print(f"    comments       = 'proxmox vmid={v.vmid} node={v.node}'")
        print(f"    cf.proxmox_vmid= {v.vmid}")
        print(f"    tags           = [proxmox_import]")

        print(f"    data source    = {v.data_source}"
              + ("  (SSH ground truth)" if v.data_source == "ssh"
                 else "  (guest agent)" if v.data_source == "agent"
                 else "  (proxmox config only — no live IPs)"))

        nic_macs = {n.mac for n in v.nics}
        all_addrs = v.ssh_addrs or v.agent_addrs  # SSH preferred
        primary_v4 = v.mgmt_ip
        primary_v6 = next(
            (a.ip for a in all_addrs
             if ":" in a.ip and a.mac in nic_macs), None)

        print(f"    interfaces ({len(v.nics)}):")
        for nic in v.nics:
            # Interface name + IPs from SSH ground truth (else agent); bridge/VLAN
            # only Proxmox knows. Joined by MAC.
            ifname = v.ifname_for_mac(nic.mac) or nic.key
            ips = v.addrs_for_mac(nic.mac)
            origin = "guest" if v.ifname_for_mac(nic.mac) else f"proxmox {nic.key}, NO guest name"
            vlan = f", untagged_vlan={nic.vlan}" if nic.vlan is not None else ""
            print(f"        VMInterface {ifname}  mac={nic.mac}  "
                  f"({origin}; bridge {nic.bridge}{vlan})")
            for a in ips:
                marks = []
                if a.ip == primary_v4:
                    marks.append(f"primary_ip4, dns_name={v.canonical_fqdn}")
                if a.ip == primary_v6:
                    marks.append(f"primary_ip6, dns_name={v.canonical_fqdn}")
                tag = f"   [{'; '.join(marks)}]" if marks else ""
                print(f"            IPAddress {a.ip}/{a.prefix}{tag}")
            if not ips:
                print(f"            (no IPs — VM unreachable / agent off)")
        # Guest interfaces not tied to a Proxmox vNIC (docker/overlay/tailscale).
        others = sorted({(a.ifname, a.ip) for a in all_addrs if a.mac not in nic_macs})
        if others:
            print("        other guest interfaces (not modeled as vNICs): "
                  + ", ".join(f"{ip}({name})" for name, ip in others))
        if primary_v4 is None and v.status == "running":
            print("    !! no mgmt IPv4 — primary_ip4 + host-map entry MISSING "
                  "(VM unreachable by SSH and no agent)")

    print(f"\n{would_sync} VM(s) would sync to NetBox; {skipped} skipped.")


# ── NetBox writer (idempotent upsert) ─────────────────────────────────
#
# Writes are gated behind --commit (default is a dry run that only reads NetBox
# and logs what it would do). Matching is by the proxmox_vmid custom field +
# cluster (stable across VM renames), falling back to (name, cluster). Every
# object created/updated carries the `proxmox_import` tag; tags are only added,
# never removed, so hand-applied tags on adopted objects survive.

CLUSTER_TYPE = ("Proxmox", "proxmox")        # (name, slug)
IMPORT_TAG_SLUG = "proxmox-import"
IMPORT_TAG = {"slug": IMPORT_TAG_SLUG}
VMID_CF = "proxmox_vmid"


def _first(results):
    return next(iter(results), None)


def _field_changed(obj, key, desired) -> bool:
    cur = getattr(obj, key, None)
    if key == "tags":
        have = {t.slug for t in (cur or [])}
        want = {t["slug"] if isinstance(t, dict) else t for t in desired}
        return not want.issubset(have)          # add-only
    if key == "custom_fields":
        cf = dict(cur or {})
        return any(cf.get(k) != v for k, v in desired.items())
    if key == "status":
        return (cur.value if hasattr(cur, "value") else cur) != desired
    if hasattr(cur, "id"):                       # FK Record
        return cur.id != desired
    return cur != desired


def _upsert(ep, existing, desired: dict, dry_run: bool, label: str):
    """Create or patch a NetBox object; returns the object (None on dry-run create)."""
    if existing is None:
        logger.info(f"{'[DRY-RUN] would create' if dry_run else 'creating'} {label}")
        if dry_run:
            return None
        return ep.create(**{k: v for k, v in desired.items() if v is not None})
    diffs = {k: v for k, v in desired.items() if _field_changed(existing, k, v)}
    if diffs:
        logger.info(f"{'[DRY-RUN] would update' if dry_run else 'updating'} "
                    f"{label}: {sorted(diffs)}")
        if not dry_run:
            existing.update(diffs)
    else:
        logger.debug(f"no change: {label}")
    return existing


def ensure_scaffold(nb, sites_needed: Set[str], dry_run: bool) -> dict:
    """Ensure cluster type, per-site clusters, import tag, and the vmid custom field."""
    ct = _first(nb.virtualization.cluster_types.filter(slug=CLUSTER_TYPE[1]))
    if not ct:
        logger.info(f"{'[DRY-RUN] would create' if dry_run else 'creating'} "
                    f"cluster-type {CLUSTER_TYPE[0]}")
        ct = None if dry_run else nb.virtualization.cluster_types.create(
            name=CLUSTER_TYPE[0], slug=CLUSTER_TYPE[1])

    if not _first(nb.extras.tags.filter(slug=IMPORT_TAG_SLUG)):
        logger.info(f"{'[DRY-RUN] would create' if dry_run else 'creating'} "
                    f"tag {IMPORT_TAG_SLUG}")
        if not dry_run:
            nb.extras.tags.create(name="proxmox_import", slug=IMPORT_TAG_SLUG)

    cf = _first(nb.extras.custom_fields.filter(name=VMID_CF))
    if not cf:
        logger.info(f"{'[DRY-RUN] would create' if dry_run else 'creating'} "
                    f"custom field {VMID_CF}")
        if not dry_run:
            try:
                cf = nb.extras.custom_fields.create(
                    object_types=["virtualization.virtualmachine"],
                    name=VMID_CF, type="integer", label="Proxmox VMID",
                    description="Proxmox VM id; discovery match key")
            except Exception as e:  # noqa: BLE001
                logger.warning(f"could not create custom field {VMID_CF} "
                               f"({e}); will match VMs by name instead")

    clusters = {}
    for slug in sorted(sites_needed):
        site = nb.dcim.sites.get(slug=slug)
        if not site:
            logger.warning(f"NetBox Site '{slug}' not found — VMs there will be skipped")
            continue
        cl = _first(nb.virtualization.clusters.filter(name=slug))
        if not cl:
            logger.info(f"{'[DRY-RUN] would create' if dry_run else 'creating'} "
                        f"cluster {slug}")
            if not dry_run:
                cl = nb.virtualization.clusters.create(
                    name=slug, type=(ct.id if ct else None), site=site.id)
        clusters[slug] = cl
    return {"cluster_type": ct, "cf": bool(cf), "clusters": clusters}


def _set_mac(nb, iface, mac: str, dry_run: bool) -> None:
    """Attach a MAC to a VMInterface (best-effort; NetBox 4.2+ uses MACAddress objects)."""
    if iface is None:
        return
    macs_ep = getattr(getattr(nb, "dcim", None), "mac_addresses", None)
    try:
        if macs_ep is not None:                  # modern NetBox (>=4.2)
            existing = _first(macs_ep.filter(mac_address=mac))
            if existing is None:
                logger.info(f"{'[DRY-RUN] would attach' if dry_run else 'attaching'} "
                            f"MAC {mac}")
                if not dry_run:
                    m = macs_ep.create(
                        mac_address=mac,
                        assigned_object_type="virtualization.vminterface",
                        assigned_object_id=iface.id)
                    iface.update({"primary_mac_address": m.id})
        elif not dry_run:                        # legacy field
            iface.update({"mac_address": mac})
    except Exception as e:  # noqa: BLE001
        logger.warning(f"MAC {mac} attach failed (NetBox version?): {e}")


def _resolve_vlan(nb, vid: Optional[int], site_slug: str):
    """NetBox VLAN id for a vid (prefer the cluster's site), or None if absent."""
    if vid is None:
        return None
    vl = _first(nb.ipam.vlans.filter(vid=vid, site=site_slug)) \
        or _first(nb.ipam.vlans.filter(vid=vid))
    return vl.id if vl else None


def _free_primary(nb, ip, new_iface, dry_run: bool) -> None:
    """NetBox won't reassign an IP that is its current parent's primary_ip — clear
    that pointer first when we're moving the IP to a different interface."""
    aoid = getattr(ip, "assigned_object_id", None)
    aotype = getattr(ip, "assigned_object_type", None)
    if not aoid or (new_iface is not None and aoid == new_iface.id):
        return
    parent = None
    try:
        if aotype == "virtualization.vminterface":
            oi = nb.virtualization.interfaces.get(aoid)
            if oi and oi.virtual_machine:
                parent = nb.virtualization.virtual_machines.get(oi.virtual_machine.id)
        elif aotype == "dcim.interface":
            oi = nb.dcim.interfaces.get(aoid)
            if oi and oi.device:
                parent = nb.dcim.devices.get(oi.device.id)
    except Exception:  # noqa: BLE001
        return
    if not parent:
        return
    clear = {f: None for f in ("primary_ip4", "primary_ip6")
             if getattr(parent, f, None) and getattr(parent, f).id == ip.id}
    if clear:
        logger.info(f"clearing {sorted(clear)} on "
                    f"{getattr(parent, 'name', parent)} to free IP {ip.address}")
        if not dry_run:
            parent.update(clear)


def _sync_ip(nb, iface, addr: str, dns_name: str, dry_run: bool,
             allow_adopt: bool = True):
    existing = None
    if iface is not None:
        existing = _first(nb.ipam.ip_addresses.filter(address=addr, vminterface_id=iface.id))
    # allow_adopt=False for shared IPs (same addr intentionally on >1 host on
    # different VLANs) — don't steal another interface's object; create our own.
    if existing is None and allow_adopt:
        existing = _first(nb.ipam.ip_addresses.filter(address=addr))
        if existing is not None:
            _free_primary(nb, existing, iface, dry_run)
    desired = {
        "address": addr, "status": "active",
        "assigned_object_type": "virtualization.vminterface",
        "assigned_object_id": iface.id if iface else None,
        "tags": [IMPORT_TAG],
    }
    if dns_name:
        desired["dns_name"] = dns_name
    return _upsert(nb.ipam.ip_addresses, existing, desired, dry_run, f"    ip {addr}")


def _ambiguous_ips(vms: List[VM]) -> Set[str]:
    """IPs claimed by >1 running host (shared service/VRRP/anycast) — they can't
    map to a single canonical host, so they're excluded from NetBox + host-map."""
    owners: Dict[str, Set[str]] = {}
    for vm in vms:
        if is_stale(vm.name) or vm.status != "running":
            continue
        nic_macs = {n.mac for n in vm.nics}
        for a in (vm.ssh_addrs or vm.agent_addrs):
            if a.mac in nic_macs:
                owners.setdefault(a.ip, set()).add(vm.canonical_fqdn)
    return {ip for ip, hosts in owners.items() if len(hosts) > 1}


def sync_vm(nb, vm: VM, scaffold: dict, dry_run: bool,
            ambiguous_ips: Set[str] = frozenset()) -> None:
    cl = scaffold["clusters"].get(vm.cluster)
    clid = cl.id if cl else None
    if clid is None and not dry_run:
        logger.warning(f"no cluster for {vm.cluster}; skipping {vm.canonical_fqdn}")
        return

    existing = None
    if scaffold["cf"] and clid:
        existing = _first(nb.virtualization.virtual_machines.filter(
            cf_proxmox_vmid=vm.vmid, cluster_id=clid))
    if existing is None and clid:
        existing = _first(nb.virtualization.virtual_machines.filter(
            name=vm.canonical_fqdn, cluster_id=clid))

    desired = {
        "name": vm.canonical_fqdn,
        "cluster": clid,
        "status": "active" if vm.status == "running" else "offline",
        "vcpus": vm.vcpus,
        "memory": vm.memory_mb,
        "disk": round(vm.disk_gb * 1024) if vm.disk_gb else None,  # NetBox VM disk is MB
        "comments": f"proxmox vmid={vm.vmid} node={vm.node}"
                    + (f"; os={vm.platform}" if vm.platform else ""),
        "custom_fields": {VMID_CF: vm.vmid},
        "tags": [IMPORT_TAG],
    }
    vmobj = _upsert(nb.virtualization.virtual_machines, existing, desired, dry_run,
                    f"VM {vm.canonical_fqdn} [{vm.cluster}]")

    # Interfaces (named from the guest) + their IPs, joined to Proxmox by MAC.
    nic_macs = {n.mac for n in vm.nics}
    all_addrs = vm.ssh_addrs or vm.agent_addrs
    primary_v4 = vm.mgmt_ip
    primary_v6 = next((a.ip for a in all_addrs
                       if ":" in a.ip and a.mac in nic_macs), None)
    primary = {}
    for nic in vm.nics:
        ifname = vm.ifname_for_mac(nic.mac) or nic.key
        desc = (f"proxmox {nic.key} bridge {nic.bridge}"
                + (f" vlan {nic.vlan}" if nic.vlan is not None else ""))
        idesired = {"virtual_machine": vmobj.id if vmobj else None, "name": ifname,
                    "description": desc, "tags": [IMPORT_TAG]}
        vlan_id = _resolve_vlan(nb, nic.vlan, vm.cluster)
        if vlan_id:
            idesired["mode"] = "access"
            idesired["untagged_vlan"] = vlan_id
        iface_existing = (_first(nb.virtualization.interfaces.filter(
            virtual_machine_id=vmobj.id, name=ifname)) if vmobj else None)
        iface = _upsert(nb.virtualization.interfaces, iface_existing, idesired,
                        dry_run, f"  iface {vm.canonical_fqdn}/{ifname}")
        _set_mac(nb, iface, nic.mac, dry_run)
        for a in vm.addrs_for_mac(nic.mac):
            addr = f"{a.ip}/{a.prefix}"
            dns = vm.canonical_fqdn if a.ip in (primary_v4, primary_v6) else ""
            # Shared IPs (same addr on >1 host, different VLANs) get their own
            # IPAddress object per interface rather than being reassigned.
            try:
                ipobj = _sync_ip(nb, iface, addr, dns, dry_run,
                                 allow_adopt=(a.ip not in ambiguous_ips))
            except Exception as e:  # noqa: BLE001 - one bad IP shouldn't abort the VM
                logger.error(f"    ip {addr} failed: {e}")
                continue
            if a.ip == primary_v4 and ipobj:
                primary["primary_ip4"] = ipobj.id
            if a.ip == primary_v6 and ipobj:
                primary["primary_ip6"] = ipobj.id

    if vmobj and primary:
        diffs = {k: v for k, v in primary.items() if _field_changed(vmobj, k, v)}
        if diffs:
            logger.info(f"{'[DRY-RUN] would set' if dry_run else 'setting'} "
                        f"primary IP(s) on {vm.canonical_fqdn}: {sorted(diffs)}")
            if not dry_run:
                vmobj.update(diffs)


def sync_to_netbox(nb, vms: List[VM], dry_run: bool) -> None:
    syncable = [v for v in vms if not is_stale(v.name) and v.status == "running"]
    sites = {v.cluster for v in syncable}
    scaffold = ensure_scaffold(nb, sites, dry_run)
    unverified = [v.canonical_fqdn for v in syncable if not v.identity_verified]
    if unverified:
        logger.warning(f"{len(unverified)} VM(s) have UNVERIFIED identity "
                       f"(no SSH/agent) — names are guesses: {', '.join(unverified)}")
    ambiguous = _ambiguous_ips(syncable)
    if ambiguous:
        logger.info(f"{len(ambiguous)} IP(s) shared across hosts (same IP on "
                    f"different VLANs) — modeled separately per host: "
                    f"{', '.join(sorted(ambiguous))}")
    for vm in syncable:
        try:
            sync_vm(nb, vm, scaffold, dry_run, ambiguous)
        except Exception as e:  # noqa: BLE001
            logger.error(f"sync failed for {vm.canonical_fqdn}: {e}")
    logger.info(f"{'DRY-RUN: ' if dry_run else ''}processed {len(syncable)} VM(s)")


def generate_host_map(vms: List[VM], path: Optional[str]) -> None:
    """Emit the syslog-ng add-contextual-data CSV: <source-ip>,host,<fqdn>.

    A host can forward syslog from ANY of its interface IPs (mgmt, peering, v6),
    so emit one row per real vNIC IP — all mapping to the same canonical FQDN.
    IPs are matched to a Proxmox vNIC by MAC, which excludes docker/overlay noise.
    """
    ambiguous = _ambiguous_ips(vms)
    if ambiguous:
        logger.warning(f"{len(ambiguous)} IP(s) shared by multiple hosts — omitted "
                       f"from host-map (ambiguous source): {', '.join(sorted(ambiguous))}")
    rows: Set[tuple] = set()
    skipped = 0
    for vm in vms:
        if is_stale(vm.name) or vm.status != "running":
            continue
        if not vm.identity_verified:
            skipped += 1
            continue
        nic_macs = {n.mac for n in vm.nics}
        ips = {a.ip for a in (vm.ssh_addrs or vm.agent_addrs)
               if a.mac in nic_macs and a.ip not in ambiguous}
        if not ips and vm.mgmt_ip and vm.mgmt_ip not in ambiguous:  # last resort
            ips = {vm.mgmt_ip}
        if not ips:
            skipped += 1
            continue
        for ip in ips:
            rows.add((ip, vm.canonical_fqdn))
    # Context name must match the syslog-ng add-contextual-data lookup
    # (${canonical_host}); the production map is generated by netbox_syslog_hostmap.py.
    body = "".join(f"{ip},canonical_host,{fqdn}\n" for ip, fqdn in sorted(rows))
    if path:
        with open(path, "w") as f:
            f.write(body)
        logger.info(f"wrote host-map ({len(rows)} entries) to {path}")
    else:
        print("\n# host-map.csv (source-ip,canonical_host,canonical-fqdn)")
        print(body, end="")
    if skipped:
        logger.warning(f"{skipped} running VM(s) omitted from host-map "
                       "(no verified identity / mgmt IP)")


# ── CLI ───────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list-vms", action="store_true",
                    help="Enumerate Proxmox VMs and print a report (no writes)")
    ap.add_argument("--netbox-preview", action="store_true",
                    help="Show the NetBox objects a sync would create (no writes)")
    ap.add_argument("--include-offline", action="store_true",
                    help="Include stopped/offline VMs in the preview (default: skip)")
    ap.add_argument("--ssh-enrich", action="store_true",
                    help="SSH into running VMs for FQDN/source-IP/OS/services")
    ap.add_argument("--ssh-user", default=None, metavar="USER",
                    help="SSH user for --ssh-enrich (default: your SSH config user)")
    ap.add_argument("--netbox", action="store_true",
                    help="Cross-reference against existing NetBox VMs (read-only)")
    ap.add_argument("--inventory", metavar="PATH",
                    help="Cross-reference against an Ansible inventory file")
    ap.add_argument("--env", metavar="PATH",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         ".env"),
                    help="dotenv file with NETBOX_API_* (default: .env next to this script)")
    ap.add_argument("--cluster", action="append", metavar="SITE",
                    help=f"Limit to cluster(s): {', '.join(PROXMOX_CLUSTERS)}")
    ap.add_argument("--vm", action="append", metavar="SUBSTR",
                    help="Limit to VMs whose Proxmox name contains SUBSTR")
    ap.add_argument("--jump", metavar="HOST",
                    help="SSH ProxyJump host to reach the mgmt network")
    ap.add_argument("--sync", action="store_true",
                    help="Upsert discovered VMs/interfaces/IPs into NetBox "
                         "(DRY-RUN unless --commit)")
    ap.add_argument("--commit", action="store_true",
                    help="With --sync, actually write to NetBox (default: dry run)")
    ap.add_argument("--generate-host-map", nargs="?", const="-", metavar="PATH",
                    dest="host_map", default=None,
                    help="Emit syslog-ng host-map CSV (to PATH, or stdout if omitted)")
    args = ap.parse_args()

    if not (args.list_vms or args.netbox_preview or args.sync
            or args.host_map is not None):
        ap.error("nothing to do; pass --list-vms / --netbox-preview / --sync / "
                 "--generate-host-map")

    clusters = args.cluster or list(PROXMOX_CLUSTERS)
    if unknown := set(clusters) - set(PROXMOX_CLUSTERS):
        ap.error(f"unknown cluster(s): {', '.join(sorted(unknown))}")

    # --sync / --generate-host-map need SSH ground truth too.
    enrich = args.ssh_enrich or args.netbox_preview or args.sync \
        or args.host_map is not None
    netbox_names = load_netbox_names(args.env) if args.netbox else None
    inventory = load_inventory_hosts(args.inventory)

    all_vms: List[VM] = []
    for cluster in clusters:
        try:
            vms = enumerate_cluster_vms(
                cluster, PROXMOX_CLUSTERS[cluster], args.jump, args.vm)
        except Exception as e:  # noqa: BLE001
            logger.error(f"Enumeration failed for cluster {cluster}: {e}")
            continue
        for v in vms:
            if enrich and v.status == "running":
                ssh_enrich(v, args.jump, user=args.ssh_user)
            dns_crosscheck(v)
            if netbox_names is not None:
                v.in_netbox = v.name in netbox_names
            if inventory is not None:
                v.in_inventory = v.canonical_fqdn in inventory
        all_vms.extend(vms)

    if args.list_vms:
        print_report(all_vms, inventory)
    if args.netbox_preview:
        netbox_preview(all_vms, include_offline=args.include_offline)
    if args.sync:
        nb = get_netbox_api(args.env)
        if nb is None:
            logger.error("cannot --sync: NetBox API unavailable")
            return 2
        if not args.commit:
            logger.warning("DRY RUN (no --commit): NetBox will not be modified")
        sync_to_netbox(nb, all_vms, dry_run=not args.commit)
    if args.host_map is not None:
        generate_host_map(all_vms, None if args.host_map == "-" else args.host_map)
    return 0


if __name__ == "__main__":
    sys.exit(main())
