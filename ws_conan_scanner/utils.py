import argparse

import csv
import io
import json
import subprocess

import requests


def csv_to_json(csvFilePath):
    r_bytes = requests.get(csvFilePath).content
    r = r_bytes.decode('utf8')
    reader = csv.DictReader(io.StringIO(r))
    result_csv_reader = json.dumps(list(reader))
    json_result = json.loads(result_csv_reader)
    return json_result


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 'True', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'False', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def execute_command(command,logger):

    try:
        logger.info(f"Going to run the following command : {command}")
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode()
        logger.info(output)
        return output
    except subprocess.CalledProcessError as e:
        logger.error(e.output.decode())


def create_logger(args):
    import sys
    import logging
    from logging.handlers import RotatingFileHandler
    from pathlib import Path
    from ws_conan_scanner._version import __tool_name__
    from conan_scanner import DATE_TIME_NOW
    import os

    logger = logging.getLogger(__tool_name__)
    logger.setLevel(logging.DEBUG if bool(os.environ.get("DEBUG", 0)) else logging.INFO)

    formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s', datefmt='%a, %d %b %Y %H:%M:%S')

    if args.get('log_file_path'):
        fh = RotatingFileHandler(Path(args.get('log_file_path'), f'{__tool_name__}_log_{DATE_TIME_NOW}.log'))
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    return logger
