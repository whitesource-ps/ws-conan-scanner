import argparse

import csv
import io
import json

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
