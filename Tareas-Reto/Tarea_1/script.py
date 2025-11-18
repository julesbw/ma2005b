import subprocess

PCAP_FILE = "dns_mx_traza.pcapng"

DOMINIOS = [
    "tec.mx",
    "unam.mx",
    "gob.mx",
    "sat.gob.mx",
    "bbva.mx",
    "banorte.com.mx",
    "coppel.com.mx",
    "liverpool.com.mx",
    "milenio.com.mx",
    "oxxo.com.mx",
]


# --------------------------
# Función auxiliar para ejecutar tshark
# --------------------------
def run_tshark(domain, fields):
    try:
        cmd = [
            "tshark",
            "-r", PCAP_FILE,
            "-Y", f"dns.qry.name == \"{domain}\"",
            "-T", "fields"
        ]

        for field in fields:
            cmd += ["-e", field]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return []

        lines = result.stdout.strip().split("\n")
        values = []

        for line in lines:
            if not line.strip():
                continue

            for part in line.split():
                values.append(part)

        return values

    except Exception as e:
        print(f"[ERROR ejecutando tshark para {domain}]: {e}")
        return []


# --------------------------
# Limpia lista → divide por coma → quita duplicados → ordena
# --------------------------
def limpiar(lista):
    limpio = set()
    for item in lista:
        for part in item.split(","):
            part = part.strip()
            if part:
                limpio.add(part)
    return sorted(limpio)


# --------------------------
# Análisis principal
# --------------------------
def analizar_dominio(domain):
    registros = {
        "A": limpiar(run_tshark(domain, ["dns.a"])),
        "AAAA": limpiar(run_tshark(domain, ["dns.aaaa"])),
        "NS": limpiar(run_tshark(domain, ["dns.ns"])),
        "CNAME": limpiar(run_tshark(domain, ["dns.cname"])),
        "SOA": limpiar(run_tshark(domain, ["dns.soa.mname"])),
    }

    print(f"\n=== {domain} ===")
    for tipo, valores in registros.items():
        print(f"- Registros {tipo} ({len(valores)}): {valores}")


# --------------------------
# Programa principal
# --------------------------
def main():
    for d in DOMINIOS:
        analizar_dominio(d)


if __name__ == "__main__":
    main()
