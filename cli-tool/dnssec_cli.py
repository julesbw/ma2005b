import subprocess
import tempfile
import pyshark
import os
import sys
import dns.message
import dns.query
import dns.flags

BOLD = "\033[1m"
RESET = "\033[0m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"

def dnssec_query(domain):
    print(f"{CYAN}📡 Realizando consulta DNSSEC desde Python...{RESET}")

    query = dns.message.make_query(domain, "DNSKEY", want_dnssec=True)
    query.flags |= dns.flags.AD  # Authenticated Data

    try:
        dns.query.udp(query, "8.8.8.8", timeout=2)
    except Exception as e:
        print(f"Error en consulta DNSSEC: {e}")

def capture_traffic(domain, duration=2):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng")
    path = tmp_file.name
    tmp_file.close()

    print(f"{CYAN}🎧 Capturando tráfico DNS con tshark...{RESET}")

    cmd = [
        "tshark", "-w", path,
        "-a", f"duration:{duration}",
        "-f", "udp port 53"
    ]

    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path

def parse_pcapng(path):
    print(f"{CYAN}🔍 Analizando {path}...{RESET}\n")
    cap = pyshark.FileCapture(path, display_filter="dns")

    result = {
        "DNSKEY": [],
        "DS": [],
        "RRSIG": [],
        "NSEC": [],
        "NSEC3": [],
        "NSEC3PARAM": []
    }

    for pkt in cap:
        dns = pkt.dns

        # DNSKEY
        if hasattr(dns, "dnskey_algorithm"):
            result["DNSKEY"].append({
                "algorithm": dns.dnskey_algorithm,
                "flags": dns.dnskey_flags,
                "ttl": dns.get_field_value("dnskey_ttl")
            })

        # DS
        if hasattr(dns, "ds_key_id"):
            result["DS"].append({
                "key_id": dns.ds_key_id,
                "digest_type": dns.ds_digest_type,
                "ttl": dns.get_field_value("ds_ttl")
            })

        # RRSIG
        if hasattr(dns, "rrsig_type_covered"):
            result["RRSIG"].append({
                "type": dns.rrsig_type_covered,
                "algorithm": dns.rrsig_algorithm,
                "ttl": dns.get_field_value("rrsig_ttl")
            })

        # NSEC
        if hasattr(dns, "nsec_next_domain_name"):
            result["NSEC"].append({
                "next_domain": dns.nsec_next_domain_name,
                "ttl": dns.get_field_value("nsec_ttl")
            })

        # NSEC3
        if hasattr(dns, "nsec3_salt_value"):
            result["NSEC3"].append({
                "salt": dns.nsec3_salt_value,
                "iterations": dns.nsec3_iterations,
                "ttl": dns.get_field_value("nsec3_ttl")
            })

    cap.close()
    return result

def print_report(domain, data):
    print(f"\n{BOLD}{GREEN}=== RESULTADOS PARA {domain} ==={RESET}\n")

    for rtype, entries in data.items():
        print(f"{YELLOW}► {rtype} ({len(entries)}){RESET}")
        for e in entries:
            print(f"   - {e}")
        print()

def main():
    if len(sys.argv) < 2:
        print("Uso: python dnssec_cli.py <dominio.mx>")
        sys.exit(1)

    domain = sys.argv[1]

    dnssec_query(domain)
    pcap = capture_traffic(domain)
    data = parse_pcapng(pcap)
    print_report(domain, data)
    os.remove(pcap)

if __name__ == "__main__":
    main()
