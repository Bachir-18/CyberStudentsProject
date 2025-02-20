import logging

# Configuration du logger
logger = logging.getLogger('mon_logger')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('/var/log/osint/osint.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)
