import sys
from ip_utils import check_ip
from shodan_utils import shodan_info
from virus_total_utils import check_virustotal_ip
from dns_utils import get_domain,get_dns_records
from logs import logger
from datetime import datetime, timezone
import json

def get_ip_info(ip, ip_info_vt, ip_info_shodan, domain, dns_records, file_ip):
    """Combine les données de VirusTotal, Shodan, DNS, domaine et fichier source en un dictionnaire structuré."""
    
    if ip_info_vt is None:
        analysis_date = "UNKNOWN"
        vt_info = {
            "scan_date": analysis_date,
            "network": "UNKNOWN",
            "country": "UNKNOWN",
            "continent": "UNKNOWN",
            "asn": "UNKNOWN",
            "as_owner": "UNKNOWN",
            "rir": "UNKNOWN",
            "malicious_score": 0,
            "harmless_score": 0,
            "suspicious_score": 0,
            "url": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }
    else:
        analysis_timestamp = ip_info_vt.get("last_analysis_date", 0)
        analysis_date = (
            datetime.fromtimestamp(analysis_timestamp, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            if analysis_timestamp else "UNKNOWN"
        )
        vt_info = {
            "scan_date": analysis_date,
            "network": ip_info_vt.get("network", "UNKNOWN"),
            "country": ip_info_vt.get("country", "UNKNOWN"),
            "continent": ip_info_vt.get("continent", "UNKNOWN"),
            "asn": ip_info_vt.get("asn", "UNKNOWN"),
            "as_owner": ip_info_vt.get("as_owner", "UNKNOWN"),
            "rir": ip_info_vt.get("regional_internet_registry", "UNKNOWN"),
            "malicious_score": ip_info_vt.get("last_analysis_stats", {}).get("malicious", 0),
            "harmless_score": ip_info_vt.get("last_analysis_stats", {}).get("harmless", 0),
            "suspicious_score": ip_info_vt.get("last_analysis_stats", {}).get("suspicious", 0),
            "url": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }
    
    if ip_info_shodan is None:
        shodan_info = {
            "Domains": [],
            "Hostnames": "UNKNOWN",
            "Country": "UNKNOWN",
            "City": "UNKNOWN",
            "ISP": "UNKNOWN",
            "ASN": "UNKNOWN",
            "Ports": "UNKNOWN",
            "Operating System": "UNKNOWN",
            "Services": []
        }
    else:
        shodan_info = {
            "Domains": ip_info_shodan.get("domains", []),  
            "Hostnames": ", ".join(ip_info_shodan.get("hostnames", [])), 
            "Country": ip_info_shodan.get("country_name", "UNKNOWN"),
            "City": ip_info_shodan.get("city", "UNKNOWN"),
            "ISP": ip_info_shodan.get("isp", "UNKNOWN"),
            "ASN": ip_info_shodan.get("asn", "UNKNOWN"),
            "Ports": ", ".join(map(str, ip_info_shodan.get("ports", []))), 
            "Operating System": ip_info_shodan.get("os", "UNKNOWN"),
            "Services": []
        }

        for service in ip_info_shodan.get("data", []):
            service_info = {
                "Port": service.get("port"),
                "Product": service.get("product", "UNKNOWN"),
                "Version": service.get("version", "UNKNOWN"),
                "Latitude": service.get("location", {}).get("latitude", "UNKNOWN"),
                "Longitude": service.get("location", {}).get("longitude", "UNKNOWN"),
                "Fingerprint": service.get("ssh", {}).get("fingerprint", "UNKNOWN") if "ssh" in service else "N/A"
            }
            shodan_info["Services"].append(service_info)

    dns_info = {
        "Domain": domain,
        "DNS Records": dns_records
    }

    # Fusion de toutes les informations dans un dictionnaire final
    final_info = {
        "ip":ip,
        "VirusTotal Info": vt_info,
        "Shodan Info": shodan_info,
        "DNS Info": dns_info,
        "Source File": file_ip  
    }

    return final_info

def save_ip_info(ip, ip_data):
    """Sauvegarde les informations d'une IP dans un fichier JSON."""
    with open("/var/log/osint/ip_info.json", "a") as f:
        json.dump(ip_data, f, indent=4)
        f.write("\n")
    logger.info(f"Informations de l'IP {ip} sauvegardées.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        logger.error("Usage: python3 analyse_ip.py <ip> ")
        sys.exit(1)

    ip = sys.argv[1]
    dns_records = {}

    file_ip = check_ip(ip)
    ip_info_vt = check_virustotal_ip(ip)
    ip_info_shodan = shodan_info(ip)
    domain = get_domain(ip)
    if domain :
        dns_records = get_dns_records(domain)

    save_ip_info(ip,get_ip_info(ip,ip_info_vt,ip_info_shodan,domain,dns_records, file_ip))
