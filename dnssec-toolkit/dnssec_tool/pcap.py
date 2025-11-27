import pyshark
from rich.console import Console

console = Console()

def analyze_pcap(file):
    try:
        cap = pyshark.FileCapture(file, display_filter="dns")

        dnssec_types = {"DNSKEY", "RRSIG", "DS", "NSEC", "NSEC3"}

        found = {t: 0 for t in dnssec_types}

        for pkt in cap:
            if "DNS" not in pkt:
                continue
            if hasattr(pkt.dns, "qry_type"):
                qtype = pkt.dns.qry_type
                type_name = pkt.dns.qry_type.showname

                for t in dnssec_types:
                    if t in type_name:
                        found[t] += 1
        
        console.print("[green]Resultados DNSSEC encontrados en el PCAP:[/green]")
        for k, v in found.items():
            console.print(f" - {k}: {v}")

        cap.close()

    except Exception as e:
        console.print(f"[red]Error leyendo captura:[/red] {e}")
