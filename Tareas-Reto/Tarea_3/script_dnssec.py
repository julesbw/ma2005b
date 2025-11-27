import pyshark

PCAP_FILE = "Tareas-Reto/Tarea_3/dnssec_queries.pcapng"

DNSSEC_TYPES = ["DNSKEY", "RRSIG", "DS", "NSEC", "NSEC3", "NSEC3PARAM"]

def detectar_dnssec(pkt):
    """ Detecta qué registro DNSSEC contiene el paquete """
    dns = pkt.dns
    encontrados = []

    for layer_field in dns.field_names:
        field_upper = layer_field.upper()
        for registro in DNSSEC_TYPES:
            if registro in field_upper:
                encontrados.append(registro)
                break

    return list(set(encontrados))


def extraer_campos(pkt, reg):
    """ Extrae todos los campos disponibles para un tipo DNSSEC """
    dns = pkt.dns
    datos = {}

    for field in dns.field_names:
        if reg.lower() in field.lower():
            try:
                valor = getattr(dns, field)
                datos[field] = str(valor)
            except:
                pass

    # Extrae TTL si existe
    ttl = getattr(dns, "resp_ttl", None)
    if ttl:
        datos["TTL"] = ttl

    return datos


def analizar_pcap(pcap):
    print("\n=== ANALISIS DNSSEC COMPLETO ===\n")
    cap = pyshark.FileCapture(pcap, display_filter="dns")

    dominios = {}

    for pkt in cap:
        if "DNS" not in pkt:
            continue

        dns = pkt.dns

        try:
            dominio = dns.qry_name if hasattr(dns, "qry_name") else "desconocido"
        except:
            dominio = "desconocido"

        encontrados = detectar_dnssec(pkt)
        if not encontrados:
            continue

        if dominio not in dominios:
            dominios[dominio] = {r: [] for r in DNSSEC_TYPES}

        for reg in encontrados:
            campos = extraer_campos(pkt, reg)
            dominios[dominio][reg].append(campos)

    cap.close()
    return dominios


def imprimir(d):
    for dominio, regs in d.items():
        print(f"\n===== {dominio} =====")
        for reg, lista in regs.items():
            if lista:
                print(f"\n ► {reg} ({len(lista)})")
                for entry in lista:
                    print("   -", entry)


def main():
    datos = analizar_pcap(PCAP_FILE)
    imprimir(datos)


if __name__ == "__main__":
    main()
