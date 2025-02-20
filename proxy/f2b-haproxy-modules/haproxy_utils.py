import subprocess
import os
from logs import logger
import sys

blocklist_file = "/etc/haproxy/blocklist.lst"

def run_socat(command):
    """Exécute une commande socat pour communiquer avec la socket HAProxy"""
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors de l'exécution de socat : {e}")

def ip_ban(ip):
    """Ban une IP et ajoute ses informations dans VirusTotal et Shodan"""
    logger.info(f"Bannissement de l'IP : {ip}")
    run_socat(f"echo 'add acl {blocklist_file} {ip}' | socat stdio unix-connect:/run/haproxy/admin.sock")
    os.system(f"echo {ip} >> {blocklist_file}")
    
def ip_unban(ip):
    """Unban une IP et la supprime des fichiers HAProxy"""
    logger.info(f"Débannissement de l'IP : {ip}")
    run_socat(f"echo 'del acl {blocklist_file} {ip}' | socat stdio unix-connect:/run/haproxy/admin.sock")
    os.system(f"sed -i '/{ip}/d' {blocklist_file}")
    os.system(f"jq 'select(.ip != \"{ip}\")' /var/log/osint/ip_info.json | sudo sponge /var/log/osint/ip_info.json")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        logger.error("Usage: python3 analyse_ip.py <ip> (ban|unban)")
        sys.exit(1)

    ip = sys.argv[1]
    action = sys.argv[2]

    if action not in ["ban", "unban"]:
        logger.error("Usage: python3 analyse_ip.py <ip> (ban|unban)")
        sys.exit(1)

    if action == "ban":
        ip_ban(ip)
    else:
        ip_unban(ip)
