import shodan
from logs import logger

SHODAN_API_KEY = "YOUR API KEY"

def shodan_info(ip):
    """Retourne les informations récupérées via Shodan"""
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        ip_info = api.host(ip)
        return ip_info
    except shodan.APIError as e:
        logger.error(f"Erreur Shodan pour {ip}: {e}")
        return None
