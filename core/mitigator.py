"""
Attack Mitigator
Provides countermeasures for each detected attack type.
Runs system commands to block/recover from attacks.
"""

import subprocess
import shutil
import platform
from datetime import datetime


IS_TERMUX = False
try:
    with open("/proc/version") as f:
        if "android" in f.read().lower():
            IS_TERMUX = True
except Exception:
    pass

IS_ROOT = False
try:
    import os
    IS_ROOT = (os.geteuid() == 0)
except Exception:
    pass


def _run(cmd, shell=False):
    """Run a shell command, return (success, output)"""
    try:
        result = subprocess.run(
            cmd if shell else cmd.split(),
            capture_output=True, text=True, timeout=10, shell=shell
        )
        out = (result.stdout + result.stderr).strip()
        return result.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError as e:
        return False, f"Command not found: {e}"
    except Exception as e:
        return False, str(e)


def _has_cmd(cmd):
    return shutil.which(cmd) is not None


# ── Mitigation Actions ────────────────────────────────────────────────────────

def mitigate_arp_spoofing(alert):
    """
    Fix ARP Spoofing:
    1. Add static ARP entry for the victim IP with its real MAC
    2. Flush ARP cache
    3. Block attacker MAC via iptables (if root)
    """
    steps = []
    source_ip  = alert.get("source_ip", "")
    old_mac    = alert.get("old_mac", "")
    source_mac = alert.get("source_mac", "")

    if not source_ip:
        return {"success": False, "steps": [], "summary": "No source IP in alert"}

    # Step 1: Set static ARP entry (restore real MAC)
    if old_mac and old_mac != "N/A":
        ok, out = _run(f"arp -s {source_ip} {old_mac}", shell=True)
        steps.append({
            "action": f"Set static ARP: {source_ip} → {old_mac}",
            "command": f"arp -s {source_ip} {old_mac}",
            "success": ok,
            "output": out or "Done"
        })
    else:
        steps.append({
            "action": "Static ARP skipped (original MAC unknown)",
            "command": "-",
            "success": True,
            "output": "Cannot restore without original MAC"
        })

    # Step 2: Flush ARP cache
    if _has_cmd("ip"):
        ok, out = _run("ip neigh flush all", shell=True)
        steps.append({
            "action": "Flush ARP cache",
            "command": "ip neigh flush all",
            "success": ok,
            "output": out or "ARP cache flushed"
        })

    # Step 3: Block attacker MAC via iptables (root only)
    if IS_ROOT and source_mac and source_mac != "N/A" and _has_cmd("iptables"):
        ok, out = _run(
            f"iptables -A INPUT -m mac --mac-source {source_mac} -j DROP",
            shell=True
        )
        steps.append({
            "action": f"Block attacker MAC {source_mac} via iptables",
            "command": f"iptables -A INPUT -m mac --mac-source {source_mac} -j DROP",
            "success": ok,
            "output": out or "MAC blocked"
        })
    elif not IS_ROOT:
        steps.append({
            "action": "Block attacker MAC (skipped — needs root)",
            "command": f"iptables -A INPUT -m mac --mac-source {source_mac} -j DROP",
            "success": False,
            "output": "Run as root/sudo for full mitigation"
        })

    success = any(s["success"] for s in steps)
    return {
        "success": success,
        "steps": steps,
        "summary": "ARP cache restored. Static entry added to prevent re-poisoning." if success
                   else "Partial mitigation — run as root for full protection."
    }


def mitigate_deauth_attack(alert):
    """
    Fix Deauth Attack:
    1. Block attacker MAC via iptables
    2. Log to system (for awareness)
    3. Suggest enabling 802.11w (Management Frame Protection)
    """
    steps = []
    source_ip  = alert.get("source_ip", "")
    source_mac = alert.get("source_mac", "")

    # Step 1: Block IP via iptables
    if source_ip and IS_ROOT and _has_cmd("iptables"):
        ok, out = _run(f"iptables -A INPUT -s {source_ip} -j DROP", shell=True)
        ok2, out2 = _run(f"iptables -A OUTPUT -d {source_ip} -j DROP", shell=True)
        steps.append({
            "action": f"Block attacker IP {source_ip} (INPUT + OUTPUT)",
            "command": f"iptables -A INPUT -s {source_ip} -j DROP && iptables -A OUTPUT -d {source_ip} -j DROP",
            "success": ok,
            "output": (out + " | " + out2).strip() or "IP blocked"
        })
    elif source_ip and not IS_ROOT:
        steps.append({
            "action": f"Block IP {source_ip} (skipped — needs root)",
            "command": f"iptables -A INPUT -s {source_ip} -j DROP",
            "success": False,
            "output": "Run as root/sudo to block IP"
        })

    # Step 2: Block MAC if available
    if source_mac and source_mac != "N/A" and IS_ROOT and _has_cmd("iptables"):
        ok, out = _run(
            f"iptables -A INPUT -m mac --mac-source {source_mac} -j DROP",
            shell=True
        )
        steps.append({
            "action": f"Block attacker MAC {source_mac}",
            "command": f"iptables -A INPUT -m mac --mac-source {source_mac} -j DROP",
            "success": ok,
            "output": out or "MAC blocked"
        })

    # Step 3: Advisory
    steps.append({
        "action": "Enable 802.11w (Management Frame Protection) on router",
        "command": "# Configure via router admin panel → Wireless Security → MFP: Required",
        "success": True,
        "output": "Advisory: Enable MFP on your WiFi router to prevent deauth attacks"
    })

    success = any(s["success"] for s in steps)
    return {
        "success": success,
        "steps": steps,
        "summary": f"Attacker {source_ip} blocked. Enable 802.11w on router for permanent fix."
    }


def mitigate_dns_spoofing(alert):
    """
    Fix DNS Spoofing:
    1. Flush DNS cache
    2. Set trusted DNS servers (8.8.8.8, 1.1.1.1)
    3. Block rogue DNS server IP
    """
    steps = []
    source_ip = alert.get("source_ip", "")

    # Step 1: Flush DNS cache
    flushed = False
    if _has_cmd("systemd-resolve"):
        ok, out = _run("systemd-resolve --flush-caches", shell=True)
        steps.append({
            "action": "Flush DNS cache (systemd-resolved)",
            "command": "systemd-resolve --flush-caches",
            "success": ok,
            "output": out or "DNS cache flushed"
        })
        flushed = ok

    if not flushed and _has_cmd("resolvectl"):
        ok, out = _run("resolvectl flush-caches", shell=True)
        steps.append({
            "action": "Flush DNS cache (resolvectl)",
            "command": "resolvectl flush-caches",
            "success": ok,
            "output": out or "DNS cache flushed"
        })
        flushed = ok

    if not flushed:
        steps.append({
            "action": "Flush DNS cache",
            "command": "systemd-resolve --flush-caches",
            "success": False,
            "output": "systemd-resolve not found. Try: sudo service nscd restart"
        })

    # Step 2: Set trusted DNS via resolv.conf (root only)
    if IS_ROOT:
        try:
            with open("/etc/resolv.conf", "w") as f:
                f.write("# Set by WiFi Monitor - trusted DNS\n")
                f.write("nameserver 8.8.8.8\n")
                f.write("nameserver 1.1.1.1\n")
                f.write("nameserver 9.9.9.9\n")
            steps.append({
                "action": "Set trusted DNS servers (8.8.8.8, 1.1.1.1, 9.9.9.9)",
                "command": "echo 'nameserver 8.8.8.8\\nnameserver 1.1.1.1' > /etc/resolv.conf",
                "success": True,
                "output": "DNS set to Google + Cloudflare + Quad9"
            })
        except Exception as e:
            steps.append({
                "action": "Set trusted DNS servers",
                "command": "echo 'nameserver 8.8.8.8' > /etc/resolv.conf",
                "success": False,
                "output": str(e)
            })
    else:
        steps.append({
            "action": "Set trusted DNS (skipped — needs root)",
            "command": "echo 'nameserver 8.8.8.8\\nnameserver 1.1.1.1' > /etc/resolv.conf",
            "success": False,
            "output": "Run as root to override DNS settings"
        })

    # Step 3: Block rogue DNS server
    if source_ip and IS_ROOT and _has_cmd("iptables"):
        ok, out = _run(
            f"iptables -A INPUT -s {source_ip} -p udp --sport 53 -j DROP",
            shell=True
        )
        steps.append({
            "action": f"Block rogue DNS responses from {source_ip}",
            "command": f"iptables -A INPUT -s {source_ip} -p udp --sport 53 -j DROP",
            "success": ok,
            "output": out or "Rogue DNS blocked"
        })

    success = any(s["success"] for s in steps)
    return {
        "success": success,
        "steps": steps,
        "summary": "DNS cache flushed. Trusted DNS servers configured." if success
                   else "DNS flush attempted. Run as root for full protection."
    }


def mitigate_dhcp_starvation(alert):
    """
    Fix DHCP Starvation:
    1. Block attacker MAC via iptables (DHCP port)
    2. Block attacker IP
    """
    steps = []
    source_ip  = alert.get("source_ip", "")
    source_mac = alert.get("source_mac", "")

    # Step 1: Block MAC from sending DHCP requests
    if source_mac and source_mac != "N/A" and IS_ROOT and _has_cmd("iptables"):
        ok, out = _run(
            f"iptables -A INPUT -m mac --mac-source {source_mac} -p udp --dport 67 -j DROP",
            shell=True
        )
        steps.append({
            "action": f"Block DHCP requests from MAC {source_mac}",
            "command": f"iptables -A INPUT -m mac --mac-source {source_mac} -p udp --dport 67 -j DROP",
            "success": ok,
            "output": out or "DHCP requests from attacker blocked"
        })
    elif not IS_ROOT:
        steps.append({
            "action": f"Block DHCP from MAC {source_mac} (skipped — needs root)",
            "command": f"iptables -A INPUT -m mac --mac-source {source_mac} -p udp --dport 67 -j DROP",
            "success": False,
            "output": "Run as root/sudo to block DHCP flood"
        })

    # Step 2: Block IP
    if source_ip and IS_ROOT and _has_cmd("iptables"):
        ok, out = _run(f"iptables -A INPUT -s {source_ip} -j DROP", shell=True)
        steps.append({
            "action": f"Block attacker IP {source_ip}",
            "command": f"iptables -A INPUT -s {source_ip} -j DROP",
            "success": ok,
            "output": out or "IP blocked"
        })

    # Step 3: Advisory
    steps.append({
        "action": "Enable DHCP Snooping on managed switch/router",
        "command": "# Configure via router admin panel → DHCP Snooping",
        "success": True,
        "output": "Advisory: Enable DHCP Snooping to prevent future starvation attacks"
    })

    success = any(s["success"] for s in steps)
    return {
        "success": success,
        "steps": steps,
        "summary": f"DHCP flood from {source_mac or source_ip} blocked." if success
                   else "Advisory issued. Run as root for active blocking."
    }


def mitigate_port_scan(alert):
    """
    Fix Port Scan / SYN Flood:
    1. Block attacker IP via iptables
    2. Enable SYN cookies (kernel protection)
    3. Rate-limit connections from that IP
    """
    steps = []
    source_ip = alert.get("source_ip", "")
    attack_type = alert.get("type", "PORT_SCAN")

    # Step 1: Block IP
    if source_ip and IS_ROOT and _has_cmd("iptables"):
        ok, out = _run(f"iptables -A INPUT -s {source_ip} -j DROP", shell=True)
        steps.append({
            "action": f"Block attacker IP {source_ip}",
            "command": f"iptables -A INPUT -s {source_ip} -j DROP",
            "success": ok,
            "output": out or "IP blocked"
        })
    elif source_ip and not IS_ROOT:
        steps.append({
            "action": f"Block IP {source_ip} (skipped — needs root)",
            "command": f"iptables -A INPUT -s {source_ip} -j DROP",
            "success": False,
            "output": "Run as root/sudo to block IP"
        })

    # Step 2: Enable SYN cookies (for SYN flood)
    if attack_type == "SYN_FLOOD" and IS_ROOT:
        ok, out = _run("sysctl -w net.ipv4.tcp_syncookies=1", shell=True)
        steps.append({
            "action": "Enable TCP SYN cookies (kernel DoS protection)",
            "command": "sysctl -w net.ipv4.tcp_syncookies=1",
            "success": ok,
            "output": out or "SYN cookies enabled"
        })

    # Step 3: Rate-limit new connections from that IP
    if source_ip and IS_ROOT and _has_cmd("iptables"):
        ok, out = _run(
            f"iptables -A INPUT -s {source_ip} -p tcp --syn -m limit --limit 1/s -j ACCEPT",
            shell=True
        )
        steps.append({
            "action": f"Rate-limit TCP SYN from {source_ip} (1/sec)",
            "command": f"iptables -A INPUT -s {source_ip} -p tcp --syn -m limit --limit 1/s -j ACCEPT",
            "success": ok,
            "output": out or "Rate limit applied"
        })

    success = any(s["success"] for s in steps)
    return {
        "success": success,
        "steps": steps,
        "summary": f"IP {source_ip} blocked. SYN protection enabled." if success
                   else f"Advisory: block {source_ip} manually. Run as root for auto-block."
    }


def mitigate_rogue_dhcp(alert):
    """Block rogue DHCP server"""
    steps = []
    rogue_ip = alert.get("rogue_server", alert.get("source_ip", ""))

    if rogue_ip and IS_ROOT and _has_cmd("iptables"):
        ok, out = _run(
            f"iptables -A INPUT -s {rogue_ip} -p udp --sport 67 -j DROP",
            shell=True
        )
        steps.append({
            "action": f"Block rogue DHCP server {rogue_ip}",
            "command": f"iptables -A INPUT -s {rogue_ip} -p udp --sport 67 -j DROP",
            "success": ok,
            "output": out or "Rogue DHCP server blocked"
        })
    else:
        steps.append({
            "action": f"Block rogue DHCP {rogue_ip} (skipped — needs root)",
            "command": f"iptables -A INPUT -s {rogue_ip} -p udp --sport 67 -j DROP",
            "success": False,
            "output": "Run as root/sudo to block rogue DHCP"
        })

    success = any(s["success"] for s in steps)
    return {
        "success": success,
        "steps": steps,
        "summary": f"Rogue DHCP server {rogue_ip} blocked." if success
                   else f"Run as root to block rogue DHCP server {rogue_ip}."
    }


# ── Dispatch ──────────────────────────────────────────────────────────────────

MITIGATORS = {
    "ARP_SPOOFING":       mitigate_arp_spoofing,
    "GRATUITOUS_ARP":     mitigate_arp_spoofing,
    "DEAUTH_ATTACK":      mitigate_deauth_attack,
    "DNS_SPOOFING":       mitigate_dns_spoofing,
    "DHCP_STARVATION":    mitigate_dhcp_starvation,
    "ROGUE_DHCP":         mitigate_rogue_dhcp,
    "PORT_SCAN":          mitigate_port_scan,
    "SYN_FLOOD":          mitigate_port_scan,
    "ICMP_SWEEP":         mitigate_port_scan,
    "DANGEROUS_PORT_ACCESS": mitigate_port_scan,
}


def run_mitigation(alert):
    """
    Run the appropriate mitigation for an alert.
    Returns a result dict with steps and summary.
    """
    attack_type = alert.get("type", "UNKNOWN")
    fn = MITIGATORS.get(attack_type)

    if not fn:
        return {
            "success": False,
            "steps": [],
            "summary": f"No mitigation available for attack type: {attack_type}"
        }

    result = fn(alert)
    result["attack_type"] = attack_type
    result["source_ip"] = alert.get("source_ip", "N/A")
    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["is_root"] = IS_ROOT
    return result


def get_mitigation_preview(attack_type, source_ip):
    """Return what commands WOULD be run (for preview in UI before confirming)"""
    previews = {
        "ARP_SPOOFING": [
            f"arp -s {source_ip} <original_mac>",
            "ip neigh flush all",
            f"iptables -A INPUT -m mac --mac-source <attacker_mac> -j DROP"
        ],
        "DEAUTH_ATTACK": [
            f"iptables -A INPUT -s {source_ip} -j DROP",
            f"iptables -A OUTPUT -d {source_ip} -j DROP",
            "# Enable 802.11w on router (Management Frame Protection)"
        ],
        "DNS_SPOOFING": [
            "systemd-resolve --flush-caches",
            "echo 'nameserver 8.8.8.8' > /etc/resolv.conf",
            f"iptables -A INPUT -s {source_ip} -p udp --sport 53 -j DROP"
        ],
        "DHCP_STARVATION": [
            f"iptables -A INPUT -m mac --mac-source <mac> -p udp --dport 67 -j DROP",
            f"iptables -A INPUT -s {source_ip} -j DROP",
            "# Enable DHCP Snooping on router"
        ],
        "ROGUE_DHCP": [
            f"iptables -A INPUT -s {source_ip} -p udp --sport 67 -j DROP"
        ],
        "PORT_SCAN": [
            f"iptables -A INPUT -s {source_ip} -j DROP",
            f"iptables -A INPUT -s {source_ip} -p tcp --syn -m limit --limit 1/s -j ACCEPT"
        ],
        "SYN_FLOOD": [
            f"iptables -A INPUT -s {source_ip} -j DROP",
            "sysctl -w net.ipv4.tcp_syncookies=1",
            f"iptables -A INPUT -s {source_ip} -p tcp --syn -m limit --limit 1/s -j ACCEPT"
        ],
    }
    return previews.get(attack_type, [f"iptables -A INPUT -s {source_ip} -j DROP"])
