# dnssec_tool/cli.py

import click
from rich.console import Console
from dnssec_tool.dig import dig_capture, dig_basic, dig_exists
from dnssec_tool.parser import parse_pcap, parse_dig_output

console = Console()


@click.group()
def cli():
    """DNSSEC Toolkit CLI"""


# =============================
# Comando principal: scan
# =============================
@cli.command()
@click.argument("domain")
@click.option("--deep", is_flag=True, help="Ejecuta consultas extendidas DNSSEC.")
def scan(domain, deep):
    console.print(f"[bold cyan]🔍 DNSSEC Scan para:[/] {domain}")

    if not dig_exists():
        console.print("[red]❌ 'dig' no está instalado.[/]")
        return

    # --- 1) Intentar captura PCAP ---
    pcap = dig_capture(domain, deep=deep)

    if pcap:
        records = parse_pcap(pcap)
        if records:
            return print_records(records)

    # --- 2) Fallback: salida directa de dig ---
    dig_output = dig_basic(domain, deep=deep)
    records = parse_dig_output(dig_output)

    console.print("[yellow]⚠ Analizando salida de texto (sin PCAP).[/]")
    print_records(records)



def print_records(records):
    console.print("\n[green]=== RESULTADOS DNSSEC ===[/]")

    if not records:
        console.print("[yellow]⚠ No se encontraron registros.[/]")
        return

    for rtype, items in records.items():
        if not items:
            continue

        console.print(f"\n[bold cyan]{rtype} ({len(items)})[/]")
        for item in items:
            console.print(f"  - {item}")


# =============================
# Subcomando: tree
# =============================
@cli.command()
@click.argument("domain")
def tree(domain):
    """Muestra el árbol DNS: raíz -> TLD -> dominio → subdominios."""
    console.print(f"[bold cyan]🌳 Árbol DNS para:[/] {domain}")

    tld = domain.split(".")[-1]

    tree = f"""
.
└── ROOT
    └── .{tld}
        └── {domain}
    """

    console.print(tree)


def main():
    cli()


if __name__ == "__main__":
    main()