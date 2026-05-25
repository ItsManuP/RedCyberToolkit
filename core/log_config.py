# core/log_config.py
import logging
import sys

def setup_logging(level=logging.INFO):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)-5s] [%(name)s] %(message)s', datefmt='%H:%M:%S'))
    logging.basicConfig(level=level, handlers=[handler], force=True)

def get_logger(name):
    return logging.getLogger(name)