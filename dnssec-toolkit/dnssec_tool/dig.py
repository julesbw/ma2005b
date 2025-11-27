# dnssec_tool/dig.py

import subprocess
import shutil
import tempfile
import os
import time
from rich.console import Console

console = Console()


def dig_exists():
    return shutil.which("dig") is not None


def tshark_exists():
    return shutil.which("tshark") is not None


# ---------------------------
# Comandos extendidos
# ---------------------------
def build_deep_commands(domain):
    tld = domain.split(".")[-1]

    commands = [
        ["dig", domain, "DNSKEY", "+dnssec"],
        ["dig", domain, "DS", "+dnssec"],
        ["dig", domain, "SOA", "+dnssec"],
        ["dig", domain, "NS", "+dnssec"],
        ["dig", domain, "NSEC", "+dnssec"],
        ["dig", domain, "NSEC3", "+dnssec"],
        ["dig", domain, "NSEC3PARAM", "+dnssec"],
        ["dig", domain, "ANY", "+dnssec"],
        ["dig", domain, "trace", "+dnssec"],

        # TLD
        ["dig", tld, "DNSKEY", "+dnssec"],
        ["dig", tld, "DS", "+dnssec"],
    ]

    return commands


# ---------------------------
# Método básico (fallback)
# ---------------------------
def dig_basic(domain, deep=False):

    if not deep:
        cmd = ["dig", domain, "DNSKEY", "DS", "+dnssec"]
    else:
        cmd = ["dig", domain, "ANY", "+dnssec"]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except Exception as e:
        console.print(f"[red]Error ejecutando dig:[/] {e}")
        return ""


# ---------------------------
# Captura PCAP
# ---------------------------
def dig_capture(domain, deep=False):

    if not tshark_exists():
        return None

    pcap = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{domain}.pcapng").name

    console.print("[cyan]📡 Iniciando captura con tshark...[/]")

    capture = subprocess.Popen(
        ["tshark", "-w", pcap, "udp port 53"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(0.3)

    if deep:
        cmds = build_deep_commands(domain)
    else:
        cmds = [["dig", domain, "DNSKEY", "+dnssec"]]

    # Ejecutar consultas
    for cmd in cmds:
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

    time.sleep(0.3)
    capture.terminate()

    if os.path.getsize(pcap) < 150:
        return None

    console.print(f"[green]✔ Captura completada:[/] {pcap}")
    return pcap
