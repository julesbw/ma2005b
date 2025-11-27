import pyshark
from rich.console import Console

console = Console()

DNSSEC_TYPES = {
    "DNSKEY": "dns.dnskey_flags",
    "DS": "dns.ds_key_tag",
    "RRSIG": "dns.rrsig_type_covered",
    "NSEC": "dns.nsec_next_domain_name",
    "NSEC3": "dns.nsec3_hash_algo",
    "NSEC3PARAM": "dns.nsec3param_hash_algorithm"
}


def parse_dnssec_records(pcap_file: str):
    """
    Parsea registros DNSSEC desde un archivo PCAP.
    """
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    results = {t: [] for t in DNSSEC_TYPES}

    for pkt in cap:
        if "DNS" not in pkt:
            continue

        for rtype, field in DNSSEC_TYPES.items():
            try:
                value = pkt.dns.get_field_value(field)
                if value:
                    results[rtype].append(value)
            except:
                pass

    return results
