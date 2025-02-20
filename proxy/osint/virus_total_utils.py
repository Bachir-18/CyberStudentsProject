import requests
from logs import logger

VT_API_KEY = 'YOUR API KEY'

def check_virustotal_ip(ip):
    """Interroge VirusTotal pour récupérer les informations sur l'IP."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data["data"]["attributes"] if "data" in data else None
    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur lors de la récupération de l'IP {ip} : {e}")
        return None

def check_virustotal_domain(domain):
    """Interroge VirusTotal pour récupérer les informations sur un domaine."""
    logger.info(f"Vérification du domaine : {domain}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data["data"]["attributes"] if "data" in data else None
    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur lors de l'interrogation de VirusTotal pour le domaine {domain}: {e}")
        return None
