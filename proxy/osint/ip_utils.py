import ipaddress
from logs import logger

def is_ip_in_file(ip, file_path):
    """Vérifie si l'IP est dans un fichier avec des IPs en CIDR"""
    try:
        with open(file_path, 'r') as file:
            cidr_list = file.read().splitlines()
        for cidr in cidr_list:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False):
                return True
        return False
    except FileNotFoundError:
        logger.error(f"Erreur : Le fichier {file_path} est introuvable.")
        return False
    except ValueError as e:
        logger.error(f"Erreur de format dans le fichier {file_path}: {e}")
        return False

def check_ip(ip):
    """Vérifie si l'IP est dans bad-ip.txt ou c2-ip.txt, et retourne le fichier où elle est trouvée."""
    files_to_check = ["list/bad-ip.txt", "list/c2-ip.txt"]
    for file in files_to_check:
        if is_ip_in_file(ip, file):
            logger.info(f"L'IP {ip} a été trouvée dans le fichier {file}.")
            return file
    return None

