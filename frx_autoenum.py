#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FRX-AutoEnum v3.0 "MATURE"  —  Advanced Automated Enumeration &
Vulnerability Hunting Framework.

    sudo python3 frx_autoenum.py -H <target> [options]

One command → full 65535 TCP port scan → deep service/version scan on
every open port → UDP scan → NSE vuln/CVE scan → parallel per-service
deep enumeration (HTTP/FTP/SSH/SMB/SNMP/DNS/SMTP/LDAP/DB/NFS/Telnet) →
exploit-DB cross-reference → discovered hostnames auto-added to
/etc/hosts → one clean colorful Markdown report.

Nothing here auto-exploits anything. It enumerates, fingerprints and
SUGGESTS candidate public exploits (searchsploit) for manual review —
exactly the OSCP methodology.
"""

import argparse
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime

VERSION = "4.0 APEX"

# =============================================================================
# COLORS + LOW-LEVEL UI PRIMITIVES
# =============================================================================
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[38;5;196m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[38;5;226m"
    GREEN  = "\033[38;5;46m"
    CYAN   = "\033[38;5;51m"
    BLUE   = "\033[38;5;33m"
    PURPLE = "\033[38;5;135m"
    PINK   = "\033[38;5;201m"
    WHITE  = "\033[97m"
    GRAY   = "\033[38;5;244m"

RAINBOW = [C.RED, C.ORANGE, C.YELLOW, C.GREEN, C.CYAN, C.BLUE, C.PURPLE, C.PINK]
ANSI_RE = re.compile(r"\033\[[0-9;]*m")
PRINT_LOCK = threading.Lock()


def strip_ansi(s):
    return ANSI_RE.sub("", s)


def vlen(s):
    return len(strip_ansi(s))


def term_width(minw=76, maxw=118):
    try:
        w = os.get_terminal_size().columns
    except OSError:
        w = 100
    return max(minw, min(w, maxw))


def rainbow(text, offset=0):
    out = ""
    for i, ch in enumerate(text):
        out += RAINBOW[(i + offset) % len(RAINBOW)] + ch
    return out + C.RESET


def info(msg):
    with PRINT_LOCK: print(f"{C.CYAN}[i]{C.RESET} {msg}")
def ok(msg):
    with PRINT_LOCK: print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):
    with PRINT_LOCK: print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):
    with PRINT_LOCK: print(f"{C.RED}[-]{C.RESET} {msg}")
def hot(msg):
    with PRINT_LOCK: print(f"{C.RED}{C.BOLD}[!!]{C.RESET} {msg}")


def _safe_wrap(line, width):
    """Wrap a (possibly ANSI-colored) line to `width` visible columns.
    Falls back to plain-text rewrap on the stripped content so a box border
    can NEVER be pushed out of alignment by an over-long line."""
    width = max(width, 10)
    if vlen(line) <= width:
        return [line]
    plain = strip_ansi(line)
    wrapped = textwrap.wrap(plain, width=width, break_long_words=True, break_on_hyphens=False)
    return wrapped or [plain[:width]]


def box(title, lines, color=C.CYAN, icon="▸"):
    width = term_width()
    inner_w = width - 4
    with PRINT_LOCK:
        print(f"{color}╔{'═'*(width-2)}╗{C.RESET}")
        t = f" {icon} {title}"
        if vlen(t) > width - 2:
            t = t[:width - 5] + "..."
        pad = width - 2 - vlen(t)
        print(f"{color}║{C.BOLD}{t}{C.RESET}{color}{' '*max(pad,0)}║{C.RESET}")
        print(f"{color}╠{'═'*(width-2)}╣{C.RESET}")
        for line in lines:
            for wl in _safe_wrap(line, inner_w):
                pad = width - 4 - vlen(wl)
                print(f"{color}║ {C.RESET}{wl}{' '*max(pad,0)}{color} ║{C.RESET}")
        print(f"{color}╚{'═'*(width-2)}╝{C.RESET}")
        print()


def section(number, title, icon="»"):
    box(f"PHASE {number} — {title}", [], color=C.PURPLE, icon=icon)


def show_cmd(cmd_str):
    """Render the command about to run inside a clean box.
    No background highlight — the command itself is shown in bold red,
    wrapped across multiple lines so the box border never breaks,
    no matter how long the command or how narrow the terminal."""
    max_box_w = term_width() - 6
    inner_w = max(max_box_w - 4, 20)
    wrapped = textwrap.wrap(cmd_str, width=inner_w, break_long_words=True, break_on_hyphens=False) or [cmd_str]
    content_w = max([vlen(w) for w in wrapped] + [vlen("RUN ▶")])
    box_w = min(max_box_w, content_w + 4)
    inner_w = box_w - 2
    with PRINT_LOCK:
        print(f"{C.GRAY}   ┌{'─'*box_w}{C.RESET}")
        label = f"{C.YELLOW}{C.BOLD}RUN ▶{C.RESET}"
        pad = inner_w - vlen("RUN ▶")
        print(f"{C.GRAY}   │{C.RESET} {label}{' '*max(pad,0)}{C.GRAY}│{C.RESET}")
        for line in wrapped:
            pad = inner_w - vlen(line)
            print(f"{C.GRAY}   │{C.RESET} {C.RED}{C.BOLD}{line}{C.RESET}{' '*max(pad,0)}{C.GRAY}│{C.RESET}")
        print(f"{C.GRAY}   └{'─'*box_w}{C.RESET}")


def print_output(text, color=C.GREEN, max_lines=None):
    """Print raw tool output highlighted in green, inside a subtle frame.
    Long lines are wrapped to the terminal width so nothing overflows."""
    if not text or not text.strip():
        return
    lines = text.rstrip("\n").splitlines()
    shown = lines if max_lines is None else lines[:max_lines]
    wrap_w = max(term_width() - 8, 40)
    with PRINT_LOCK:
        print(f"{C.GRAY}   ┄┄┄ output ┄┄┄{C.RESET}")
        for line in shown:
            for wl in (textwrap.wrap(line, width=wrap_w, break_long_words=True, break_on_hyphens=False) or [line]):
                print(f"{color}{wl}{C.RESET}")
        if max_lines and len(lines) > max_lines:
            print(f"{C.GRAY}   ... +{len(lines) - max_lines} more line(s) — full output saved in recon/{C.RESET}")
        print(f"{C.GRAY}   ┄┄┄┄┄┄┄┄┄┄┄┄┄{C.RESET}")
        print()


def print_table(headers, rows, color=C.CYAN, title=None, max_cell=48):
    if not rows:
        return

    def clip(v):
        v = str(v)
        return v if len(v) <= max_cell else v[:max_cell - 1] + "…"

    rows = [[clip(c) for c in row] for row in rows]
    widths = [vlen(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], vlen(str(cell)))

    def hline(l, m, r):
        return color + l + m.join("─" * (w + 2) for w in widths) + r + C.RESET

    with PRINT_LOCK:
        if title:
            print(f"{C.BOLD}{C.WHITE}{title}{C.RESET}")
        print(hline("┌", "┬", "┐"))
        hcells = "│".join(f" {C.BOLD}{str(h).ljust(w)}{C.RESET}{color} " for h, w in zip(headers, widths))
        print(color + "│" + hcells + "│" + C.RESET)
        print(hline("├", "┼", "┤"))
        for row in rows:
            rcells = "│".join(f" {C.RESET}{str(c).ljust(w)}{color} " for c, w in zip(row, widths))
            print(color + "│" + rcells + "│" + C.RESET)
        print(hline("└", "┴", "┘"))
        print()


# =============================================================================
# BANNER
# =============================================================================
FONT = {
    'F': ["█████", "█    ", "████ ", "█    ", "█    "],
    'R': ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    'X': ["█   █", " █ █ ", "  █  ", " █ █ ", "█   █"],
    'A': [" ███ ", "█   █", "█████", "█   █", "█   █"],
    'T': ["█████", "  █  ", "  █  ", "  █  ", "  █  "],
    'H': ["█   █", "█   █", "█████", "█   █", "█   █"],
    ' ': ["   ", "   ", "   ", "   ", "   "],
}


def print_banner():
    text = "FRX ARFATH"
    rows = ["", "", "", "", ""]
    for ch in text:
        glyph = FONT.get(ch.upper(), FONT[' '])
        for i in range(5):
            rows[i] += glyph[i] + " "

    inner_w = max(vlen(r) for r in rows) + 4
    print()
    print(f"{C.PURPLE}{C.BOLD}╔{'═'*inner_w}╗{C.RESET}")
    for i, row in enumerate(rows):
        pad = inner_w - vlen(row) - 2
        print(f"{C.PURPLE}{C.BOLD}║{C.RESET} {rainbow(row, offset=i*2)}{' '*max(pad,0)} {C.PURPLE}{C.BOLD}║{C.RESET}")
    print(f"{C.PURPLE}{C.BOLD}╚{'═'*inner_w}╝{C.RESET}")
    sub = "Advanced Auto-Enumeration & Vulnerability Hunting Framework"
    tag = (f"v{VERSION} • full 65535 TCP + top-{S.udp_top_ports if S.udp_top_ports else 1000} UDP • "
           f"CVE hunting • TLS/CORS/vhost • RDP/WinRM/Kerberos/RPC/Rsync • exploit-suggest • auto /etc/hosts")
    print(f"  {C.BOLD}{C.WHITE}{sub}{C.RESET}")
    print(f"  {C.GRAY}{tag}{C.RESET}")
    print()


# =============================================================================
# GLOBAL STATE
# =============================================================================
class State:
    host = None
    resolved_ip = None
    output_dir = None
    dns_server = None
    threads = 8
    do_udp = True
    udp_top_ports = 1000
    udp_full = False
    fast = False
    tool_timeout = 240
    start_time = 0.0

    tcp_ports = []
    services = []
    udp_ports = []
    findings = []
    exploits = []
    hostnames = set()
    hostnames_lock = threading.Lock()


S = State()


def add_hostname(h):
    if not h:
        return
    h = h.strip().lower().rstrip(".")
    if not h or h.startswith("*") or h == S.host.lower():
        return
    with S.hostnames_lock:
        if h not in S.hostnames:
            S.hostnames.add(h)
            ok(f"Discovered hostname: {C.BOLD}{h}{C.RESET}")


# =============================================================================
# HELPERS
# =============================================================================
def which(name):
    return shutil.which(name)


def need(tool, install_hint=None):
    if which(tool):
        return True
    warn(f"'{tool}' not found — skipping related checks." +
         (f" Install with: {install_hint}" if install_hint else ""))
    return False


def is_ipv4(value):
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_hostname(value):
    pattern = r'^([A-Za-z0-9-]{1,63}\.)*[A-Za-z]{2,6}$'
    return re.match(pattern, value) is not None


def get_system_dns():
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        for line in resolv.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("nameserver") and "#" not in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[-1]
    return None


def run_capture(cmd, timeout=None, shell=False):
    try:
        res = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True,
            timeout=timeout or S.tool_timeout,
        )
        return res.returncode, (res.stdout or "") + (res.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, f"[timeout after {timeout or S.tool_timeout}s]"
    except FileNotFoundError:
        return -1, "[tool not found]"
    except Exception as e:
        return -1, f"[error: {e}]"


def sh(cmd, timeout=None, shell=False):
    """Show the command in a styled box, then run it and return (rc, output)."""
    cmd_str = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd)
    show_cmd(cmd_str)
    return run_capture(cmd, timeout=timeout, shell=shell)


def save_evidence(name, content):
    path = Path("recon") / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, errors="ignore")
    return path


def ttl_to_os(ttl):
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        return "Unknown"
    if ttl in (254, 255, 256):
        return "OpenBSD/Cisco/Oracle"
    if ttl in (127, 128):
        return "Windows"
    if ttl in (63, 64):
        return "Linux/Unix"
    return "Unknown"


def ping_host(host):
    tw = "-W" if sys.platform.startswith("linux") else "-t"
    rc, out = run_capture(["ping", "-c", "1", tw, "1", host], timeout=3)
    m = re.search(r"ttl[=:](\d+)", out, re.IGNORECASE)
    if m:
        return True, m.group(1)
    return False, None


def resolve_ip(host):
    if is_ipv4(host):
        return host
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


# =============================================================================
# /etc/hosts INTEGRATION
# =============================================================================
def sync_etc_hosts():
    if not S.hostnames:
        return
    ip = S.resolved_ip or S.host
    hosts_path = Path("/etc/hosts")
    try:
        current = hosts_path.read_text()
    except Exception:
        current = ""

    to_add = [h for h in sorted(S.hostnames) if h not in current]
    if not to_add:
        info("All discovered hostnames already present in /etc/hosts.")
        return

    line = f"{ip}\t{' '.join(to_add)}\t# FRX-AutoEnum ({datetime.now().strftime('%Y-%m-%d %H:%M')})\n"
    try:
        with open(hosts_path, "a") as f:
            f.write(line)
        ok(f"Added to /etc/hosts → {ip}  {' '.join(to_add)}")
    except PermissionError:
        warn("Need root to edit /etc/hosts. Add this line manually:")
        show_cmd(f"echo '{ip} {' '.join(to_add)}' | sudo tee -a /etc/hosts")


# =============================================================================
# LIVE NMAP PROGRESS
# =============================================================================
def run_nmap_phase(number, title, extra_args, out_basename, needs_sudo=False, refresh=2):
    Path("nmap").mkdir(exist_ok=True)
    outbase = str(Path("nmap") / out_basename)
    nmap_bin = which("nmap") or "nmap"
    cmd = [nmap_bin] + extra_args + ["-oA", outbase, "--stats-every", f"{refresh}s", S.host]
    if S.dns_server:
        cmd += ["--dns-server", S.dns_server]
    if needs_sudo and os.geteuid() != 0:
        cmd = ["sudo"] + cmd

    section(number, title)
    show_cmd(" ".join(cmd))

    tmp_path = Path(outbase + ".livelog")
    try:
        with open(tmp_path, "w") as tmp_f:
            proc = subprocess.Popen(cmd, stdout=tmp_f, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        err("nmap is not installed! Cannot continue this phase.")
        return outbase

    try:
        while proc.poll() is None:
            _draw_progress(tmp_path)
            time.sleep(refresh)
        _draw_progress(tmp_path, final=True)
    except KeyboardInterrupt:
        proc.terminate()
        raise

    tmp_path.unlink(missing_ok=True)
    ok(f"Phase complete → {C.BOLD}nmap/{out_basename}.nmap{C.RESET}")
    print()
    return outbase


def _draw_progress(tmp_path, final=False):
    if not tmp_path.exists():
        if final:
            sys.stdout.write("\n")
        return
    try:
        lines = tmp_path.read_text(errors="ignore").splitlines()
    except Exception:
        return
    tail = lines[-4:] if len(lines) >= 4 else lines
    percent, elapsed, remaining, stype = 0.0, "0:00", "?", "Scanning"
    for line in tail:
        m = re.search(r"undergoing (.*) Scan", line)
        if m: stype = m.group(1)
        m = re.search(r"About ([\d.]+)% done", line)
        if m: percent = float(m.group(1))
        m = re.search(r"Stats: (.*) elapsed", line)
        if m: elapsed = m.group(1)
        m = re.search(r"\((.*) remaining", line)
        if m: remaining = m.group(1)
    width = min(term_width() - 40, 60)
    width = max(width, 15)
    filled = int(width * percent / 100)
    bar = f"{C.GREEN}{'█'*filled}{C.GRAY}{'░'*(width-filled)}{C.RESET}"
    end = "\n" if final else ""
    sys.stdout.write(
        f"\r   {C.CYAN}[{stype:<12}]{C.RESET} {bar} {C.BOLD}{percent:5.1f}%{C.RESET} "
        f"({elapsed} elapsed, {remaining} left)   {end}"
    )
    sys.stdout.flush()


# =============================================================================
# NMAP XML PARSING
# =============================================================================
def parse_open_tcp_ports(xml_path):
    ports = []
    if not Path(xml_path).exists():
        return ports
    try:
        tree = ET.parse(xml_path)
        for port_el in tree.getroot().iter("port"):
            if port_el.get("protocol") != "tcp":
                continue
            state = port_el.find("state")
            if state is not None and state.get("state") == "open":
                ports.append(int(port_el.get("portid")))
    except ET.ParseError:
        pass
    return sorted(set(ports))


def parse_services(xml_path):
    services = []
    if not Path(xml_path).exists():
        return services
    try:
        tree = ET.parse(xml_path)
        for port_el in tree.getroot().iter("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            services.append({
                "port": int(port_el.get("portid")),
                "proto": port_el.get("protocol"),
                "name": svc_el.get("name") if svc_el is not None else "unknown",
                "product": svc_el.get("product") if svc_el is not None else "",
                "version": svc_el.get("version") if svc_el is not None else "",
                "extrainfo": svc_el.get("extrainfo") if svc_el is not None else "",
            })
    except ET.ParseError:
        pass
    return services


def parse_udp_ports(xml_path):
    ports = []
    if not Path(xml_path).exists():
        return ports
    try:
        tree = ET.parse(xml_path)
        for port_el in tree.getroot().iter("port"):
            if port_el.get("protocol") != "udp":
                continue
            state = port_el.find("state")
            if state is not None and state.get("state") in ("open", "open|filtered"):
                ports.append(int(port_el.get("portid")))
    except ET.ParseError:
        pass
    return sorted(set(ports))


def extract_hostnames_from_xml(xml_path):
    found = set()
    if not Path(xml_path).exists():
        return found
    try:
        tree = ET.parse(xml_path)
        for script in tree.getroot().iter("script"):
            if script.get("id") in ("ssl-cert", "http-title", "http-server-header"):
                output = script.get("output", "") or ""
                for m in re.finditer(r"commonName=([\w.\-]+)", output):
                    found.add(m.group(1))
                for m in re.finditer(r"DNS:([\w.\-]+)", output):
                    found.add(m.group(1))
        for hostname_el in tree.getroot().iter("hostname"):
            name = hostname_el.get("name")
            if name:
                found.add(name)
    except ET.ParseError:
        pass
    return found


# =============================================================================
# NMAP PHASES
# =============================================================================
def phase_full_port_discovery():
    rate = "1000" if S.fast else "5000"
    args = ["-p-", "--min-rate", rate, "-T4", "--max-retries", "1", "--open", "-Pn"]
    outbase = run_nmap_phase(1, "Full TCP Port Discovery (all 65535 ports)", args, f"AllPorts_{S.host}")
    S.tcp_ports = parse_open_tcp_ports(outbase + ".xml")
    if S.tcp_ports:
        print_table(["Open TCP Ports"], [[p] for p in S.tcp_ports], color=C.GREEN,
                     title=f"{len(S.tcp_ports)} open TCP port(s) discovered")
    else:
        warn("No open TCP ports discovered.")
    return outbase


def phase_service_scan():
    if not S.tcp_ports:
        warn("Skipping service scan — no open ports.")
        return None
    ports_str = ",".join(map(str, S.tcp_ports))
    args = ["-sC", "-sV", "-p", ports_str, "--open", "-Pn"]
    outbase = run_nmap_phase(2, f"Deep Service/Version Scan on {len(S.tcp_ports)} port(s)",
                              args, f"Services_{S.host}")
    S.services = parse_services(outbase + ".xml")

    rows = []
    for svc in S.services:
        label = f"{svc['product']} {svc['version']} {svc['extrainfo']}".strip() or "-"
        rows.append([svc["port"], svc["proto"], svc["name"], label])
    print_table(["Port", "Proto", "Service", "Product / Version"], rows, color=C.CYAN,
                title="Detected Services")

    for h in extract_hostnames_from_xml(outbase + ".xml"):
        add_hostname(h)

    return outbase


def phase_udp_scan():
    if not S.do_udp:
        info("UDP scan disabled by user (--no-udp).")
        return None
    if S.udp_full:
        args = ["-sU", "-p-", "--open", "-Pn"]
        title = "Full UDP Port Scan (all 65535 — this is slow)"
    else:
        args = ["-sU", "--top-ports", str(S.udp_top_ports), "--open", "-Pn"]
        title = f"Top {S.udp_top_ports} UDP Port Scan"
    outbase = run_nmap_phase(3, title, args, f"UDP_{S.host}", needs_sudo=True)
    S.udp_ports = parse_udp_ports(outbase + ".xml")
    if S.udp_ports:
        print_table(["Open/Filtered UDP Ports"], [[p] for p in S.udp_ports], color=C.GREEN,
                     title=f"{len(S.udp_ports)} UDP port(s) found")
    else:
        info("No open UDP ports found.")
    return outbase


def phase_vuln_scan():
    if not S.tcp_ports:
        return None
    ports_str = ",".join(map(str, S.tcp_ports))
    vulners_present = Path("/usr/share/nmap/scripts/vulners.nse").exists()
    scripts = "vuln,vulners" if vulners_present else "vuln"
    args = ["-sV", "--script", scripts, "-p", ports_str, "--open", "-Pn"]
    if not vulners_present:
        warn("vulners.nse not installed — running generic 'vuln' category only.")
        show_cmd("sudo git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/vulners")
    outbase = run_nmap_phase(4, "NSE Vulnerability + CVE Scan (vulners)", args, f"Vulns_{S.host}")
    return outbase


# =============================================================================
# CVE EXTRACTION
# =============================================================================
def extract_cves(vulns_outbase):
    cves = []
    if not vulns_outbase:
        return cves
    p = Path(vulns_outbase + ".nmap")
    if not p.exists():
        return cves
    text = p.read_text(errors="ignore")
    for m in re.finditer(r"(CVE-\d{4}-\d{4,7})\s+([\d.]+)", text):
        cve, score = m.group(1), float(m.group(2))
        cves.append((cve, score))
    return sorted(set(cves), key=lambda x: -x[1])


def severity_color(score):
    if score >= 9.0: return C.RED, "CRITICAL"
    if score >= 7.0: return C.ORANGE, "HIGH"
    if score >= 4.0: return C.YELLOW, "MEDIUM"
    return C.GREEN, "LOW"


# =============================================================================
# EXPLOIT SUGGESTIONS
# =============================================================================
def exploit_suggestions(services_xml):
    section(5, "Exploit-DB Cross-Reference (searchsploit)")
    if not need("searchsploit", "sudo apt install exploitdb -y"):
        return

    results = []

    if Path(services_xml).exists():
        rc, out = sh(["searchsploit", "--nmap", services_xml], timeout=60)
        if out.strip():
            print_output(out)
            results.append("### searchsploit --nmap (auto cross-reference)\n```\n" + out.strip() + "\n```")

    for svc in S.services:
        product = (svc.get("product") or "").strip()
        version = (svc.get("version") or "").strip()
        if not product:
            continue
        query = f"{product} {version}".strip()
        rc, out = sh(["searchsploit", query], timeout=30)
        if "Exploits: No Results" not in out and out.strip():
            info(f"Possible exploits for {C.BOLD}{query}{C.RESET} (port {svc['port']}):")
            print_output(out)
            results.append(f"### {query}  (port {svc['port']}/{svc['proto']})\n```\n{out.strip()}\n```")

    if results:
        save_evidence("searchsploit_results.md", "\n\n".join(results))
        ok("Exploit suggestions saved → recon/searchsploit_results.md")
    else:
        info("No matching public exploits found via searchsploit for detected versions.")
    S.exploits = results


# =============================================================================
# PER-SERVICE MODULES
# =============================================================================
def _best_wordlist():
    """Pick the strongest dir-brute wordlist actually present on disk."""
    candidates = [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/big.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return "/usr/share/wordlists/dirb/common.txt"


def _check_security_headers(headers):
    """Flag missing/interesting security headers — quick OSCP-style triage."""
    lower = headers.lower()
    issues = []
    for h in ("x-frame-options", "content-security-policy", "strict-transport-security",
              "x-content-type-options"):
        if h not in lower:
            issues.append(f"missing {h}")
    if "access-control-allow-origin: *" in lower:
        issues.append("CORS: Access-Control-Allow-Origin: * (wildcard)")
    server_m = re.search(r"server:\s*(.+)", headers, re.IGNORECASE)
    if server_m:
        issues.append(f"Server header discloses: {server_m.group(1).strip()}")
    return issues


def mod_http(port, secure=False):
    scheme = "https" if secure else "http"
    url = f"{scheme}://{S.host}:{port}"
    out_lines = [f"# HTTP enum on {url}"]

    rc, headers = sh(["curl", "-sk", "-I", "-m", "10", url], timeout=15)
    print_output(headers, max_lines=12)
    out_lines.append("## Headers\n" + headers)
    for m in re.finditer(r"[Ll]ocation:\s*https?://([^/\s]+)", headers):
        add_hostname(m.group(1))

    hdr_issues = _check_security_headers(headers)
    if hdr_issues:
        out_lines.append("## Security header / CORS findings\n" + "\n".join(f"- {i}" for i in hdr_issues))
        if any("CORS" in i for i in hdr_issues):
            S.findings.append(f"**[INFO]** **HTTP {port}** — wildcard CORS header present, check for credentialed CORS abuse.")

    # CORS pre-flight probe with a foreign Origin
    rc, cors_out = sh(["curl", "-sk", "-I", "-m", "10", "-H", "Origin: https://evil.frx-test", url], timeout=15)
    if "access-control-allow-origin" in cors_out.lower():
        out_lines.append("## CORS probe (Origin: https://evil.frx-test)\n" + cors_out)

    if secure and which("sslscan"):
        rc, tls = sh(["sslscan", "--no-colour", f"{S.host}:{port}"], timeout=60)
        print_output(tls, max_lines=20)
        out_lines.append("## sslscan (TLS ciphers/protocols)\n" + tls)
    elif secure and which("testssl.sh"):
        rc, tls = sh(["testssl.sh", "--quiet", "--color", "0", f"{S.host}:{port}"], timeout=90)
        print_output(tls, max_lines=20)
        out_lines.append("## testssl.sh\n" + tls)

    rc, robots = sh(["curl", "-sk", "-m", "10", url + "/robots.txt"], timeout=15)
    if robots.strip() and "<html" not in robots.lower():
        print_output(robots, max_lines=10)
        out_lines.append("## robots.txt\n" + robots)

    rc, sitemap = sh(["curl", "-sk", "-m", "10", url + "/sitemap.xml"], timeout=15)
    if sitemap.strip() and "<html" not in sitemap.lower():
        out_lines.append("## sitemap.xml\n" + sitemap)

    tech_hint = ""
    if which("whatweb"):
        rc, ww = sh(["whatweb", "-a", "3", url], timeout=30)
        print_output(ww, max_lines=10)
        out_lines.append("## whatweb\n" + ww)
        tech_hint = ww

    if which("nikto"):
        rc, nik = sh(["nikto", "-host", url, "-maxtime", "120s"], timeout=150)
        print_output(nik, max_lines=20)
        out_lines.append("## nikto\n" + nik)

    if which("nuclei"):
        rc, nuc = sh(["nuclei", "-u", url, "-silent", "-severity", "low,medium,high,critical"], timeout=180)
        if nuc.strip():
            print_output(nuc, max_lines=20)
            out_lines.append("## nuclei (CVE/misconfig templates)\n" + nuc)
            S.findings.append(f"**[INFO]** **HTTP {port}** — nuclei returned hits, review recon/http_{port}.md")

    wordlist = _best_wordlist()
    if which("feroxbuster"):
        rc, fx = sh(
            ["feroxbuster", "-u", url, "-w", wordlist, "-t", "40", "-q", "--silent",
             "-s", "200,204,301,302,307,401,403"],
            timeout=200,
        )
        print_output(fx, max_lines=25)
        out_lines.append("## feroxbuster directory brute-force\n" + fx)
    elif which("ffuf"):
        rc, ffuf_out = sh(
            ["ffuf", "-s", "-w", f"{wordlist}", "-u", f"{url}/FUZZ",
             "-mc", "200,204,301,302,307,401,403"],
            timeout=180,
        )
        print_output(ffuf_out, max_lines=20)
        out_lines.append("## ffuf directory brute-force\n" + ffuf_out)
    elif which("gobuster"):
        rc, gb = sh(
            ["gobuster", "dir", "-w", wordlist, "-t", "30", "-u", url, "-q"],
            timeout=180,
        )
        print_output(gb, max_lines=20)
        out_lines.append("## gobuster directory brute-force\n" + gb)

    # Virtual-host / subdomain fuzzing whenever the target looks like a domain
    if is_hostname(S.host) and which("ffuf"):
        vhost_list = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if not Path(vhost_list).exists():
            vhost_list = wordlist
        rc, vhost_out = sh(
            ["ffuf", "-s", "-w", vhost_list, "-u", url,
             "-H", f"Host: FUZZ.{S.host}", "-fs", "0", "-mc", "200,301,302,403"],
            timeout=180,
        )
        if vhost_out.strip():
            print_output(vhost_out, max_lines=15)
            out_lines.append("## vhost fuzzing (Host: FUZZ." + S.host + ")\n" + vhost_out)
            for line in vhost_out.splitlines():
                m = re.match(r"^([\w-]+)", line.strip())
                if m and m.group(1):
                    add_hostname(f"{m.group(1)}.{S.host}")

    if "WordPress" in tech_hint and which("wpscan"):
        rc, wp = sh(["wpscan", "--url", url, "--no-update", "--enumerate", "p,u"], timeout=180)
        print_output(wp, max_lines=20)
        out_lines.append("## wpscan\n" + wp)

    save_evidence(f"http_{port}.md", "\n\n".join(out_lines))
    extra = " + wpscan" if "WordPress" in tech_hint else ""
    return f"HTTP/{port}: headers + TLS + CORS + robots + fingerprint + dir-brute + vhost{extra}"


def mod_ftp(port):
    lines = [f"# FTP enum on {S.host}:{port}"]
    anon = False
    try:
        import ftplib
        show_cmd(f"ftplib.connect({S.host}, {port})  # anonymous login check")
        ftp = ftplib.FTP()
        ftp.connect(S.host, port, timeout=8)
        banner = ftp.getwelcome()
        lines.append(f"Banner: {banner}")
        try:
            ftp.login("anonymous", "anonymous@")
            anon = True
            lines.append("[+] ANONYMOUS LOGIN ALLOWED!")
            try:
                listing = ftp.nlst()
                lines.append("Directory listing:\n" + "\n".join(listing))
            except Exception:
                pass
        except Exception as e:
            lines.append(f"Anonymous login failed: {e}")
        ftp.quit()
    except Exception as e:
        lines.append(f"Connection error: {e}")
    save_evidence(f"ftp_{port}.md", "\n".join(lines))
    if anon:
        S.findings.append(f"**[CRITICAL]** **FTP {port}** — anonymous login allowed!")
    return f"FTP/{port}: banner + anonymous-login check" + (" [ANON OK!]" if anon else "")


def mod_ssh(port):
    lines = [f"# SSH banner on {S.host}:{port}"]
    try:
        show_cmd(f"socket.connect({S.host}, {port})  # SSH banner grab")
        sock = socket.create_connection((S.host, port), timeout=8)
        banner = sock.recv(256).decode(errors="ignore").strip()
        lines.append(f"Banner: {banner}")
        sock.close()
    except Exception as e:
        lines.append(f"Error: {e}")
    save_evidence(f"ssh_{port}.md", "\n".join(lines))
    return f"SSH/{port}: banner grabbed"


def mod_smb(ports):
    lines = ["# SMB enumeration"]
    if which("enum4linux"):
        rc, out = sh(["enum4linux", "-a", S.host], timeout=120)
        print_output(out, max_lines=25)
        lines.append("## enum4linux -a\n" + out)
    if which("smbmap"):
        rc, out = sh(["smbmap", "-H", S.host], timeout=60)
        print_output(out, max_lines=15)
        lines.append("## smbmap\n" + out)
    if which("smbclient"):
        rc, out = sh(["smbclient", "-L", f"//{S.host}/", "-N"], timeout=30)
        print_output(out, max_lines=15)
        lines.append("## smbclient -L (null session)\n" + out)
        if "NT_STATUS_ACCESS_DENIED" not in out and "Sharename" in out:
            S.findings.append("**[CRITICAL]** **SMB** — null session share listing succeeded!")
    save_evidence("smb.md", "\n\n".join(lines))
    return f"SMB/{','.join(map(str, ports))}: enum4linux + smbmap + smbclient null-session"


def mod_snmp():
    lines = ["# SNMP enumeration (community: public)"]
    hit = False
    if which("snmp-check"):
        rc, out = sh(["snmp-check", S.host, "-c", "public"], timeout=30)
        print_output(out, max_lines=15)
        lines.append("## snmp-check\n" + out)
    if which("snmpwalk"):
        rc, out = sh(["snmpwalk", "-Os", "-c", "public", "-v1", S.host], timeout=30)
        print_output(out, max_lines=15)
        lines.append("## snmpwalk\n" + out)
        if out.strip() and "Timeout" not in out:
            hit = True
    save_evidence("snmp.md", "\n\n".join(lines))
    if hit:
        S.findings.append("**[WARNING]** **SNMP** — 'public' community string works!")
    return "SNMP/161: public community walk"


def mod_dns():
    lines = ["# DNS enumeration"]
    if which("dig"):
        rc, out = sh(["dig", "any", S.host, f"@{S.host}"], timeout=15)
        print_output(out, max_lines=15)
        lines.append("## dig ANY\n" + out)
    if which("dnsrecon"):
        rc, out = sh(["dnsrecon", "-d", S.host], timeout=60)
        print_output(out, max_lines=20)
        lines.append("## dnsrecon\n" + out)
    save_evidence("dns.md", "\n\n".join(lines))
    return "DNS/53: zone/any query + dnsrecon"


def mod_smtp(port):
    lines = [f"# SMTP enum on {S.host}:{port}"]
    try:
        show_cmd(f"socket.connect({S.host}, {port})  # SMTP banner + EHLO")
        sock = socket.create_connection((S.host, port), timeout=8)
        banner = sock.recv(256).decode(errors="ignore").strip()
        lines.append(f"Banner: {banner}")
        sock.sendall(b"EHLO frx\r\n")
        time.sleep(0.5)
        ehlo = sock.recv(1024).decode(errors="ignore")
        lines.append(f"EHLO response:\n{ehlo}")
        sock.close()
    except Exception as e:
        lines.append(f"Error: {e}")
    if which("smtp-user-enum") and Path("/usr/share/wordlists/metasploit/unix_users.txt").exists():
        rc, out = sh(
            ["smtp-user-enum", "-U", "/usr/share/wordlists/metasploit/unix_users.txt", "-t", S.host],
            timeout=60,
        )
        lines.append("## smtp-user-enum\n" + out)
    save_evidence(f"smtp_{port}.md", "\n\n".join(lines))
    return f"SMTP/{port}: banner + EHLO + user-enum"


def mod_nfs():
    lines = ["# NFS enumeration"]
    hit = False
    if which("showmount"):
        rc, out = sh(["showmount", "-e", S.host], timeout=15)
        print_output(out, max_lines=15)
        lines.append("## showmount -e\n" + out)
        if "Export list" in out and out.strip().count("\n") > 0:
            hit = True
    save_evidence("nfs.md", "\n\n".join(lines))
    if hit:
        S.findings.append("**[WARNING]** **NFS** — exported shares visible, check for no_root_squash!")
    return "NFS/2049: showmount export list"


def mod_rpc():
    lines = ["# RPC / portmapper enumeration"]
    hit = False
    if which("rpcinfo"):
        rc, out = sh(["rpcinfo", "-p", S.host], timeout=20)
        print_output(out, max_lines=20)
        lines.append("## rpcinfo -p\n" + out)
        if rc == 0 and out.strip():
            hit = True
    save_evidence("rpc.md", "\n\n".join(lines))
    if hit:
        S.findings.append("**[INFO]** **RPC/111** — portmapper reachable, check listed services for NFS/NIS.")
    return "RPC/111: rpcinfo -p"


def mod_rsync(port):
    lines = [f"# Rsync module listing on {S.host}:{port}"]
    hit = False
    if which("rsync"):
        rc, out = sh(["rsync", "-av", "--list-only", f"rsync://{S.host}:{port}/"], timeout=20)
        print_output(out, max_lines=15)
        lines.append("## rsync --list-only\n" + out)
        if rc == 0 and out.strip() and "@ERROR" not in out:
            hit = True
    save_evidence(f"rsync_{port}.md", "\n".join(lines))
    if hit:
        S.findings.append(f"**[WARNING]** **Rsync {port}** — module listing exposed without auth, check for readable/writable shares.")
    return f"Rsync/{port}: module listing"


def mod_rdp(port):
    lines = [f"# RDP enumeration on {S.host}:{port}"]
    rc, out = sh(["nmap", "-p", str(port), "--script", "rdp-ntlm-info,rdp-enum-encryption",
                  "-Pn", S.host], timeout=60)
    print_output(out, max_lines=20)
    lines.append("## nmap rdp-ntlm-info / rdp-enum-encryption\n" + out)
    m = re.search(r"NetBIOS_Domain_Name:\s*(\S+)", out)
    if m:
        lines.append(f"Domain hint: {m.group(1)}")
    if "CVE-2019-0708" in out or "BlueKeep" in out:
        S.findings.append(f"**[CRITICAL]** **RDP {port}** — possible BlueKeep (CVE-2019-0708) exposure, verify manually!")
    save_evidence(f"rdp_{port}.md", "\n\n".join(lines))
    return f"RDP/{port}: nmap NTLM-info + encryption scan"


def mod_winrm(port):
    lines = [f"# WinRM check on {S.host}:{port}"]
    scheme = "https" if port == 5986 else "http"
    rc, out = sh(["curl", "-sk", "-I", "-m", "10", f"{scheme}://{S.host}:{port}/wsman"], timeout=15)
    lines.append("## curl /wsman\n" + out)
    if "401" in out or "WWW-Authenticate" in out:
        S.findings.append(f"**[INFO]** **WinRM {port}** — service responding, try valid creds with evil-winrm.")
        show_cmd(f"evil-winrm -i {S.host} -u <user> -p <pass>{' -S' if port == 5986 else ''}")
    save_evidence(f"winrm_{port}.md", "\n".join(lines))
    return f"WinRM/{port}: /wsman probe"


def mod_kerberos(port):
    lines = [f"# Kerberos enumeration on {S.host}:{port}"]
    rc, out = sh(["nmap", "-p", str(port), "--script", "krb5-enum-users", "-Pn", S.host], timeout=60)
    print_output(out, max_lines=15)
    lines.append("## nmap krb5-enum-users (needs --script-args to pass a userlist for real hits)\n" + out)
    if which("kerbrute"):
        info("kerbrute detected — run manually with a real username list for AS-REP roasting recon:")
        show_cmd(f"kerbrute userenum -d <domain> --dc {S.host} <userlist.txt>")
    save_evidence(f"kerberos_{port}.md", "\n\n".join(lines))
    return f"Kerberos/{port}: krb5-enum-users (needs userlist for real yield)"


def mod_ldap(port):
    lines = [f"# LDAP anonymous bind check on {S.host}:{port}"]
    hit = False
    if which("ldapsearch"):
        rc, out = sh(["ldapsearch", "-x", "-h", S.host, "-p", str(port), "-s", "base"], timeout=20)
        print_output(out, max_lines=15)
        lines.append("## ldapsearch -x (anonymous)\n" + out)
        if rc == 0 and "namingContexts" in out:
            hit = True
    save_evidence(f"ldap_{port}.md", "\n".join(lines))
    if hit:
        S.findings.append("**[WARNING]** **LDAP** — anonymous bind allowed!")
    return f"LDAP/{port}: anonymous bind check"


def mod_db(port, kind):
    lines = [f"# {kind.upper()} banner/no-auth check on {S.host}:{port}"]
    if kind == "redis" and which("redis-cli"):
        rc, out = sh(["redis-cli", "-h", S.host, "-p", str(port), "PING"], timeout=10)
        lines.append("## redis-cli PING\n" + out)
        if "PONG" in out:
            S.findings.append(f"**[CRITICAL]** **Redis {port}** — no authentication required!")
    elif kind == "mongodb" and which("mongosh"):
        rc, out = sh(["mongosh", "--host", S.host, "--port", str(port), "--eval", "db.stats()"], timeout=10)
        lines.append("## mongosh db.stats()\n" + out)
        if "error" not in out.lower():
            S.findings.append(f"**[CRITICAL]** **MongoDB {port}** — no authentication required!")
    elif kind == "mssql":
        rc, out = sh(["nmap", "-p", str(port), "--script",
                      "ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info", "-Pn", S.host], timeout=60)
        print_output(out, max_lines=20)
        lines.append("## nmap ms-sql-* scripts\n" + out)
        if "Login Success" in out or "empty password" in out.lower():
            S.findings.append(f"**[CRITICAL]** **MSSQL {port}** — empty/weak sa password accepted!")
    elif kind == "oracle":
        rc, out = sh(["nmap", "-p", str(port), "--script", "oracle-tns-version,oracle-sid-brute",
                      "-Pn", S.host], timeout=90)
        print_output(out, max_lines=20)
        lines.append("## nmap oracle-tns-version / oracle-sid-brute\n" + out)
        if which("tnscmd10g"):
            rc2, ver = sh(["tnscmd10g", "version", "-h", S.host, "-p", str(port)], timeout=20)
            lines.append("## tnscmd10g version\n" + ver)
    else:
        try:
            show_cmd(f"socket.connect({S.host}, {port})  # {kind} banner grab")
            sock = socket.create_connection((S.host, port), timeout=6)
            banner = sock.recv(128)
            lines.append(f"Raw banner bytes: {banner!r}")
            sock.close()
        except Exception as e:
            lines.append(f"Error: {e}")
    save_evidence(f"{kind}_{port}.md", "\n".join(lines))
    return f"{kind.upper()}/{port}: banner + no-auth check"


def mod_telnet(port):
    lines = [f"# Telnet banner on {S.host}:{port}"]
    try:
        show_cmd(f"socket.connect({S.host}, {port})  # Telnet banner grab")
        sock = socket.create_connection((S.host, port), timeout=8)
        time.sleep(0.5)
        banner = sock.recv(512).decode(errors="ignore")
        lines.append(f"Banner:\n{banner}")
        sock.close()
    except Exception as e:
        lines.append(f"Error: {e}")
    save_evidence(f"telnet_{port}.md", "\n".join(lines))
    return f"Telnet/{port}: banner grabbed"


# =============================================================================
# DISPATCH
# =============================================================================
DB_PORT_MAP = {3306: "mysql", 5432: "postgres", 1433: "mssql", 1521: "oracle",
               6379: "redis", 27017: "mongodb"}


def dispatch_modules():
    section(6, "Per-Service Deep Enumeration (parallel)")
    if not S.services and not S.udp_ports:
        warn("Nothing to enumerate.")
        return []

    smb_ports = [s["port"] for s in S.services if s["port"] in (139, 445)]
    tasks = []

    with ThreadPoolExecutor(max_workers=S.threads) as pool:
        futures = {}
        seen_smb = False

        for svc in S.services:
            port, name = svc["port"], (svc["name"] or "").lower()

            if "https" in name or port in (443, 8443):
                futures[pool.submit(mod_http, port, True)] = f"https-{port}"
            elif "http" in name:
                futures[pool.submit(mod_http, port, False)] = f"http-{port}"
            elif "ftp" in name:
                futures[pool.submit(mod_ftp, port)] = f"ftp-{port}"
            elif "ssh" in name:
                futures[pool.submit(mod_ssh, port)] = f"ssh-{port}"
            elif port in (139, 445) and not seen_smb:
                seen_smb = True
                futures[pool.submit(mod_smb, smb_ports)] = "smb"
            elif "domain" in name or port == 53:
                futures[pool.submit(mod_dns)] = "dns"
            elif "smtp" in name:
                futures[pool.submit(mod_smtp, port)] = f"smtp-{port}"
            elif port in (389, 636):
                futures[pool.submit(mod_ldap, port)] = f"ldap-{port}"
            elif port in DB_PORT_MAP:
                futures[pool.submit(mod_db, port, DB_PORT_MAP[port])] = f"db-{port}"
            elif "telnet" in name:
                futures[pool.submit(mod_telnet, port)] = f"telnet-{port}"
            elif port == 873 or "rsync" in name:
                futures[pool.submit(mod_rsync, port)] = f"rsync-{port}"
            elif port == 3389 or "ms-wbt-server" in name or "rdp" in name:
                futures[pool.submit(mod_rdp, port)] = f"rdp-{port}"
            elif port in (5985, 5986) or "wsman" in name:
                futures[pool.submit(mod_winrm, port)] = f"winrm-{port}"
            elif port == 88 or "kerberos" in name:
                futures[pool.submit(mod_kerberos, port)] = f"kerberos-{port}"

        if 161 in S.udp_ports:
            futures[pool.submit(mod_snmp)] = "snmp"
        if 111 in S.tcp_ports or 111 in S.udp_ports:
            futures[pool.submit(mod_rpc)] = "rpc"
        if any(p in S.tcp_ports for p in (111, 2049)):
            futures[pool.submit(mod_nfs)] = "nfs"

        for fut in as_completed(futures):
            tag = futures[fut]
            try:
                result = fut.result()
                ok(result)
                tasks.append(result)
            except Exception as e:
                err(f"{tag} module failed: {e}")

    print()
    return tasks


# =============================================================================
# CONFIG CARD + REPORT
# =============================================================================
def print_config_card():
    udp_desc = "DISABLED"
    if S.do_udp:
        udp_desc = "FULL 1-65535 (slow)" if S.udp_full else f"top {S.udp_top_ports} ports"
    rows = [
        f"{C.CYAN}Target        {C.RESET}: {C.BOLD}{S.host}{C.RESET}",
        f"{C.CYAN}Output dir    {C.RESET}: {S.output_dir}",
        f"{C.CYAN}DNS server    {C.RESET}: {S.dns_server or 'system default'}",
        f"{C.CYAN}TCP scan      {C.RESET}: full 1-65535  (min-rate {'1000' if S.fast else '5000'})",
        f"{C.CYAN}UDP scan      {C.RESET}: {udp_desc}",
        f"{C.CYAN}Threads       {C.RESET}: {S.threads}",
        f"{C.CYAN}Per-tool T/O  {C.RESET}: {S.tool_timeout}s",
        f"{C.CYAN}Modules       {C.RESET}: HTTP/TLS/CORS/vhost, FTP, SSH, SMB, SNMP, DNS, SMTP,",
        f"{C.CYAN}              {C.RESET}  LDAP, SQL/Redis/Mongo, NFS, RPC, Rsync, RDP, WinRM, Kerberos",
        f"{C.CYAN}Auto /etc/hosts{C.RESET}: enabled",
        f"{C.CYAN}Started       {C.RESET}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    box("SCAN CONFIGURATION", rows, color=C.BLUE)


def write_report(vulns_outbase):
    box("GENERATING FINAL REPORT", [], color=C.PURPLE)

    elapsed = int(time.time() - S.start_time)
    m, s = divmod(elapsed, 60)
    h, m = divmod(m, 60)

    cves = extract_cves(vulns_outbase) if vulns_outbase else []

    lines = []
    lines.append(f"# FRX-AutoEnum Report — {S.host}")
    lines.append(f"_Generated: {datetime.now().isoformat(timespec='seconds')}_  ")
    lines.append(f"_Duration: {h}h {m}m {s}s_\n")

    lines.append("## Open TCP Ports")
    if S.tcp_ports:
        lines.append("| Port | Service | Product/Version |")
        lines.append("|------|---------|------------------|")
        for svc in S.services:
            label = f"{svc['product']} {svc['version']} {svc['extrainfo']}".strip()
            lines.append(f"| {svc['port']} | {svc['name']} | {label} |")
    else:
        lines.append("_None found._")

    if S.udp_ports:
        lines.append("\n## Open/Filtered UDP Ports\n")
        lines.append(", ".join(map(str, S.udp_ports)))

    if S.hostnames:
        lines.append("\n## Discovered Hostnames (auto-added to /etc/hosts)\n")
        for h_ in sorted(S.hostnames):
            lines.append(f"- {h_}")

    lines.append("\n## Vulnerabilities (CVE, from NSE vulners)")
    if cves:
        lines.append("| CVE | CVSS | Severity |")
        lines.append("|-----|------|----------|")
        for cve, score in cves:
            _, sev = severity_color(score)
            lines.append(f"| {cve} | {score} | {sev} |")
    else:
        lines.append("_None detected by vulners / vuln scripts (or tool not installed)._")

    lines.append("\n## Manual / Misconfiguration Findings")
    if S.findings:
        for f_ in S.findings:
            lines.append(f"- {f_}")
    else:
        lines.append("_No obvious misconfigurations flagged automatically — review raw evidence in `recon/`._")

    lines.append("\n## Suggested Exploits (searchsploit)")
    lines.append("See `recon/searchsploit_results.md` for full details."
                  if S.exploits else "_No candidate public exploits matched detected service versions._")

    lines.append("\n## Evidence Files")
    lines.append("All raw tool output saved under `recon/` and `nmap/` in this output directory.")

    report_path = Path(f"FRX-Report_{S.host}.md")
    report_path.write_text("\n".join(lines))

    cve_rows = [[cve, score, severity_color(score)[1]] for cve, score in cves[:15]]
    if cve_rows:
        colored_rows = []
        for cve, score, sev in cve_rows:
            color, _ = severity_color(score)
            colored_rows.append([f"{color}{cve}{C.RESET}", score, f"{color}{sev}{C.RESET}"])
        print_table(["CVE", "CVSS", "Severity"], colored_rows, color=C.RED, title="Top Vulnerabilities Found")

    summary_rows = [
        f"{C.CYAN}Target          {C.RESET}: {C.BOLD}{S.host}{C.RESET}",
        f"{C.CYAN}TCP ports open  {C.RESET}: {len(S.tcp_ports)}",
        f"{C.CYAN}UDP ports open  {C.RESET}: {len(S.udp_ports)}",
        f"{C.CYAN}Hostnames found {C.RESET}: {len(S.hostnames)}",
        f"{C.CYAN}CVEs found      {C.RESET}: {len(cves)}",
        f"{C.CYAN}Findings        {C.RESET}: {len(S.findings)}",
        f"{C.CYAN}Duration        {C.RESET}: {h}h {m}m {s}s",
        f"{C.CYAN}Report          {C.RESET}: {report_path.resolve()}",
    ]
    box("ENUMERATION COMPLETE", summary_rows, color=C.GREEN)


# =============================================================================
# MAIN
# =============================================================================
def usage(prog):
    print_banner()
    box("USAGE", [
        f"{C.YELLOW}sudo python3 {prog} -H <target> [options]{C.RESET}",
        "",
        f"{C.CYAN}-H, --host{C.RESET}        Target IP or hostname (required)",
        f"{C.CYAN}-o, --output{C.RESET}      Output directory (default: <host>)",
        f"{C.CYAN}-d, --dns{C.RESET}         Custom DNS server for lookups",
        f"{C.CYAN}--no-udp{C.RESET}          Skip UDP port scan",
        f"{C.CYAN}--udp-ports N{C.RESET}     Top-N UDP ports to scan (default 1000)",
        f"{C.CYAN}--udp-full{C.RESET}        Full 1-65535 UDP scan (very slow!)",
        f"{C.CYAN}--fast{C.RESET}            Faster/noisier TCP discovery (min-rate 1000)",
        f"{C.CYAN}--threads N{C.RESET}       Parallel enum module workers (default 8)",
        f"{C.CYAN}--timeout N{C.RESET}       Per-tool timeout in seconds (default 240)",
        "",
        f"{C.GRAY}Modules: HTTP(S)+TLS+CORS+vhost, FTP, SSH, SMB, SNMP, DNS, SMTP, LDAP,{C.RESET}",
        f"{C.GRAY}         MySQL/Postgres/MSSQL/Oracle/Redis/MongoDB, NFS, RPC, Rsync,{C.RESET}",
        f"{C.GRAY}         RDP, WinRM, Kerberos, Telnet + searchsploit cross-reference.{C.RESET}",
    ], color=C.YELLOW)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-H", "--host")
    parser.add_argument("-o", "--output")
    parser.add_argument("-d", "--dns")
    parser.add_argument("--no-udp", action="store_true")
    parser.add_argument("--udp-ports", type=int, default=1000)
    parser.add_argument("--udp-full", action="store_true")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()

    if not args.host:
        usage(sys.argv[0])

    print_banner()

    if not (is_ipv4(args.host) or is_hostname(args.host)):
        err("Invalid IP or hostname.")
        sys.exit(1)

    S.host = args.host
    S.output_dir = args.output or args.host
    S.dns_server = args.dns or get_system_dns()
    S.do_udp = not args.no_udp
    S.udp_top_ports = args.udp_ports
    S.udp_full = args.udp_full
    S.fast = args.fast
    S.threads = args.threads
    S.tool_timeout = args.timeout
    S.resolved_ip = resolve_ip(S.host)

    if not which("nmap"):
        err("nmap is required and was not found in PATH. Install: sudo apt install nmap -y")
        sys.exit(1)

    if os.geteuid() != 0:
        warn("Not running as root — UDP scan, some scripts, and /etc/hosts writes may be limited.")
        show_cmd(f"sudo python3 {sys.argv[0]} -H {S.host}")

    if is_ipv4(S.host):
        try:
            rdns = socket.gethostbyaddr(S.host)[0]
            add_hostname(rdns)
        except Exception:
            pass
    elif is_hostname(S.host):
        add_hostname(S.host)

    print_config_card()

    pingable, ttl = ping_host(S.host)
    if pingable:
        ok(f"Host is up (TTL {ttl} → likely {ttl_to_os(ttl)})")
    else:
        warn("Host did not respond to ping — continuing with -Pn (treat as up).")
    print()

    Path(S.output_dir).mkdir(parents=True, exist_ok=True)
    os.chdir(S.output_dir)
    Path("nmap").mkdir(exist_ok=True)
    Path("recon").mkdir(exist_ok=True)

    S.start_time = time.time()

    services_outbase = None
    vulns_outbase = None
    try:
        phase_full_port_discovery()
        services_outbase = phase_service_scan()
        phase_udp_scan()
        vulns_outbase = phase_vuln_scan()
        dispatch_modules()
        if services_outbase:
            exploit_suggestions(services_outbase + ".xml")
        sync_etc_hosts()
    except KeyboardInterrupt:
        warn("Interrupted — generating report with data collected so far.")
    finally:
        write_report(vulns_outbase)


if __name__ == "__main__":
    main()
