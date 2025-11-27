#!/usr/bin/env python3
import subprocess
import time

# Lista de dominios a analizar
DOMINIOS = [
    "unam.mx",
    "ipn.mx",
    "gob.mx",
    "imss.gob.mx",
    "issste.gob.mx",
    "economia.gob.mx",
    "hacienda.gob.mx",
    "segob.gob.mx",
    "sre.gob.mx",
    "cultura.gob.mx",
    "conagua.gob.mx",
    "semarnat.gob.mx",
    "salud.gob.mx",
    "profeco.gob.mx",
    "conacyt.gob.mx",
    "cfe.gob.mx",
    "inai.mx",
    "ine.mx",
    "inegi.org.mx",
    "banxico.org.mx",
    "nic.mx",
    "mxcert.org.mx",
    "anahuac.mx",
    "anahuacmayab.mx",
    "udg.mx",
    "uam.mx",
    "uanl.mx",
    "uabc.mx",
    "uv.mx",
    "unison.mx"
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
