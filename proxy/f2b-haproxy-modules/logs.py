import logging

# Configuration du logger
logger = logging.getLogger('mon_logger')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('/var/log/f2b_haproxy_modules/bun_unban.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)
