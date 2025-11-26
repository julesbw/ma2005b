import subprocess
import time

# Lista de dominios que quieras analizar (entre 5 y 10)
DOMINIOS = [
    "tec.mx",
    "unam.mx",
    "gob.mx",
    "sat.gob.mx",
    "bbva.mx",
    "banorte.com.mx",
    "coppel.com.mx",
    "liverpool.com.mx",
    "oxxo.com.mx"
]

# Tipos de consultas DNSSEC obligatorias
CONSULTAS = [
    "DNSKEY",
    "DS",
    "SOA",
    "NS",
    "A",
    "AAAA",
    "NSEC",
    "NSEC3",
    "RRSIG"
]

def dig(domain, record):
    """
    Ejecuta una consulta dig con DNSSEC habilitado.
    """
    cmd = ["dig", "+dnssec", "+multi", domain, record]
    print(f"→ Ejecutando {' '.join(cmd)}")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    print("===== INICIANDO CONSULTAS DNSSEC =====")
    print("Asegúrate de que Wireshark esté grabando...\n")
    time.sleep(2)

    for dominio in DOMINIOS:
        print(f"\n=== Dominio: {dominio} ===")
        for tipo in CONSULTAS:
            dig(dominio, tipo)
            time.sleep(0.8)   # delay para no saturar y asegurar respuestas separadas

    print("\n===== CONSULTAS COMPLETADAS =====")
    print("Ahora detén Wireshark y guarda la traza como dns_dnssec.pcapng.")

if __name__ == "__main__":
    main()
