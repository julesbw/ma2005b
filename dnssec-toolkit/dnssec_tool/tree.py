from rich.console import Console
from rich.tree import Tree
import dns.resolver
import dns.dnssec
import dns.name
import dns.exception
import base64
import hashlib

console = Console()

def build_dns_tree(domain: str) -> Tree:
    """
    Construye un árbol ASCII desde la raíz hasta el dominio dado.
    """
    labels = domain.split(".")
    tree = Tree(".")

    current = tree
    for i in range(len(labels)):
        node_name = ".".join(labels[i:])
        current = current.add(f"[cyan]{node_name}[/]")

    return tree


def get_ds(parent: str, child: str):
    """
    Obtiene el registro DS para el niño desde el dominio padre.
    """
    try:
        name = dns.name.from_text(child)
        parent_name = dns.name.from_text(parent)

        answer = dns.resolver.resolve(name, "DS")
        return [r.to_text() for r in answer]
    except Exception:
        return []


def get_dnskey(domain: str):
    """
    Obtiene los DNSKEY del dominio.
    """
    try:
        answer = dns.resolver.resolve(domain, "DNSKEY")
        return answer
    except Exception:
        return []


def dnskey_to_digest(dnskey, algorithm: int):
    """
    Calcula el digest (SHA1, SHA256) para comparar contra DS.
    """
    try:
        key = dnskey.to_text().split(" ", 3)[-1]  # Public Key
        key_bytes = base64.b64decode(key)

        if algorithm == 1:
            return hashlib.sha1(key_bytes).hexdigest()
        elif algorithm == 2:
            return hashlib.sha256(key_bytes).hexdigest()
        else:
            return None
    except Exception:
        return None


def validate_dnssec_chain(domain: str):
    """
    Valida la relación DS → DNSKEY entre padre e hijo.
    """
    labels = domain.split(".")
    if len(labels) < 2:
        return (False, "Dominio demasiado corto.")

    parent = labels[-1]      # mx
    child = domain           # unam.mx

    ds_records = get_ds(child, child)
    dnskeys = get_dnskey(child)

    if not ds_records:
        return (False, "El dominio NO tiene DS en el padre.")

    if not dnskeys:
        return (False, "El dominio NO tiene DNSKEY.")

    # Comparar digest
    for ds in ds_records:
        parts = ds.split()
        key_tag = parts[0]
        algorithm = int(parts[2])
        digest = parts[3].lower()

        for key in dnskeys:
            computed = dnskey_to_digest(key, algorithm)
            if computed == digest:
                return (True, "Cadena DNSSEC válida ✔")

    return (False, "¡Cadena rota! El DS no coincide con DNSKEY ✗")
