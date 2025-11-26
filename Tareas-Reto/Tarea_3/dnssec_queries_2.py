#!/usr/bin/env python3
import subprocess
import time

# Lista de dominios a analizar
DOMINIOS = [
    "unam.mx",
    "gob.mx",
    "sat.gob.mx",
    "tec.mx",
    "bbva.mx",
    "banorte.com.mx",
    "coppel.com.mx",
    "liverpool.com.mx",
    "oxxo.com.mx"
]

# Tipos de registros que obligan a enviar DNSSEC
REGISTROS = [
    "DNSKEY",
    "DS",
    "SOA",
    "NS",
    "A",
    "AAAA",
    "MX",
    "TXT",
]

def ejecutar_comando(cmd):
    """Ejecuta un comando en la terminal y muestra salida."""
    print(f"\n[CMD] {cmd}")
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        print(output)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {e.output}")

def consultar_dominio(dominio):
    print(f"\n==============================")
    print(f"  CONSULTANDO: {dominio}")
    print(f"==============================")

    # Consulta ANY primero (estrella para recabar todo lo posible)
    ejecutar_comando(f"dig {dominio} ANY +dnssec +multi")

    # Consultar cada tipo de registro
    for r in REGISTROS:
        ejecutar_comando(f"dig {dominio} {r} +dnssec +multi")

        # Pequeña pausa para que Wireshark capture bien
        time.sleep(1)

def main():
    print("\n===== INICIO DE CONSULTAS DNSSEC =====\n")
    
    for dom in DOMINIOS:
        consultar_dominio(dom)
        time.sleep(2)  # pausa entre dominios
    
    print("\n===== CONSULTAS DNSSEC FINALIZADAS =====\n")
    print("Ahora puedes detener la captura en Wireshark.")

if __name__ == "__main__":
    main()
