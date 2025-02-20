import dns.resolver
from logs import logger

def get_domain(ip):
    try:
        ptr_records = dns.resolver.resolve(dns.reversename.from_address(ip), 'PTR')
        for rdata in ptr_records:
            domain_full = rdata.to_text().strip('.')
            domain = domain_full.split('.', 2)[-2] + '.' + domain_full.split('.', 2)[-1]
            return domain 

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        logger.info(f"Aucun domaine trouvé pour l'adresse IP {ip} : {e}")
        return None
    except Exception as e:
        logger.error(f"Erreur lors de la recherche DNS : {e}")
        return None  


def get_dns_records(domain):
    """Récupère tous les enregistrements DNS (A, MX, NS, TXT, SOA) pour un domaine."""
    
    records = {
        "A": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "SOA": []
    }

    # Récupérer les enregistrements A (adresses IP)
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        for rdata in a_records:
            records["A"].append(rdata.to_text())
        logger.info(f"Enregistrements A pour {domain}: {records['A']}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        logger.error(f"Erreur pour l'enregistrement A de {domain}: {e}")

    # Récupérer les enregistrements MX (serveurs de messagerie)
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for rdata in mx_records:
            records["MX"].append(rdata.exchange.to_text())
        logger.info(f"Enregistrements MX pour {domain}: {records['MX']}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        logger.error(f"Erreur pour l'enregistrement MX de {domain}: {e}")

    # Récupérer les enregistrements NS (serveurs de noms)
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for rdata in ns_records:
            records["NS"].append(rdata.to_text())
        logger.info(f"Enregistrements NS pour {domain}: {records['NS']}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        logger.error(f"Erreur pour l'enregistrement NS de {domain}: {e}")

    # Récupérer les enregistrements TXT (textes, SPF, etc.)
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for rdata in txt_records:
            records["TXT"].append(rdata.to_text())
        logger.info(f"Enregistrements TXT pour {domain}: {records['TXT']}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        logger.error(f"Erreur pour l'enregistrement TXT de {domain}: {e}")

    # Récupérer les enregistrements SOA
    try:
        soa_records = dns.resolver.resolve(domain, 'SOA')
        for rdata in soa_records:
            records["SOA"].append(rdata.to_text())
        logger.info(f"Enregistrements SOA pour {domain}: {records['SOA']}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        logger.error(f"Erreur pour l'enregistrement SOA de {domain}: {e}")

    return records
