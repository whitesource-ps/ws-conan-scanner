import argparse
import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
from collections import defaultdict
from configparser import ConfigParser
from datetime import datetime
from pathlib import Path

import requests
import sys
import time
import ws_sdk
import yaml
from ws_sdk import WS, ws_constants

from model._version import __tool_name__, __version__, __description__

logging.basicConfig(level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
                    handlers=[logging.StreamHandler(stream=sys.stdout)],
                    format='%(levelname)s %(asctime)s %(thread)d %(name)s: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')

# Config file variables
DEFAULT_CONFIG_FILE = 'params.config'
CONFIG_FILE_HEADER_NAME = 'DEFAULT'

# Environment variables
WS_PREFIX = 'WS_'
WS_ENV_VARS = [WS_PREFIX + sub for sub in ('WS_URL', 'USER_KEY', 'ORG_TOKEN', 'PROJECT_PARALLELISM_LEVEL', 'PROJECT_PATH', 'PROJECT_BUILD_FOLDER_PATH')]

# API calls parameters
get_project_source_file_inventory_report = 'getProjectSourceFileInventoryReport'
get_request_state = 'getRequestState'
change_origin_library = 'changeOriginLibrary'
library_search = 'librarySearch'
REQUEST_TYPE = 'requestType'

USER_KEY = 'userKey'
PROJECT_TOKEN = 'projectToken'
PRODUCT_TOKEN = 'productToken'
PROJECT_NAME = 'projectName'
PRODUCT_NAME = 'productName'
ORG_TOKEN = 'orgToken'
PROJECT_PATH = 'projectPath'
CONAN_INSTALL_FOLDER = 'conanInstallFolder'
KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN = 'keepConanInstallFolderAfterRun'
KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN_DEFAULT_VALUE = False
FIND_MATCH_FOR_REFERENCE = 'findMatchForReference'
FIND_MATCH_FOR_REFERENCE_DEFAULTE_VALUE = False

WS_URL = 'wsUrl'
config = dict()
ws_conn = ''
PROJECT_PARALLELISM_LEVEL = 'projectParallelismLevel'
PROJECT_PARALLELISM_LEVEL_MAX_VALUE = 20
PROJECT_PARALLELISM_LEVEL_DEFAULT_VALUE = 9
PROJECT_PARALLELISM_LEVEL_RANGE = list(range(1, PROJECT_PARALLELISM_LEVEL_MAX_VALUE + 1))

WS_LOGO_URL = 'https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png'
CONAN_FILE_TXT = 'conanfile.txt'
CONAN_FILE_PY = 'conanfile.py'


# 1. validate conan is installed
def validate_conan_local_cache_folder():
    conan_home = subprocess.Popen("conan config home", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    converted_list = []

    for element in conan_home:
        if '\n' in element:
            break
        else:
            converted_list.append(element)
    conan_home = ''.join(converted_list)
    if os.path.exists(conan_home):
        logging.info(f"The conan home folder is located at : {conan_home} ")
    else:
        logging.error(f"Please check conan is installed and configured properly ")
        sys.exit(1)


# 2. validate conan project path
def validate_project_manifest_file_exists():
    logging.info(f"Checking if the conan manifest file exists in your environment.")

    if os.path.exists(os.path.join(config['project_path'], CONAN_FILE_TXT)):
        logging.info(f"The {CONAN_FILE_TXT}  manifest file exists in your environment.")
    elif os.path.exists(os.path.join(config['project_path'], CONAN_FILE_PY)):
        logging.info(f"The {CONAN_FILE_PY} manifest file exists in your environment.")
    else:
        logging.error(f"A supported manifest file was not found.")
        sys.exit(1)


# 2.conan install
def run_conan_install_command():
    if not config['conan_install_folder']:
        config['temp_dir'] = Path(config['project_path'], datetime.now().strftime('%Y%m%d%H%M%S%f'))
    elif os.path.exists(config['conan_install_folder']):
        config['temp_dir'] = config['conan_install_folder']
    else:
        logging.error(f"Please validate the conan install folder exists")
        sys.exit(1)
    os.mkdir(config['temp_dir'])
    os.system(f"conan install {config['project_path']} --install-folder {config['temp_dir']} ")


# 3.list all dependencies with: conan info DIR_CONTAINING_CONANFILE --paths --json TEMP_JSON_PATH
def list_all_dependencies():
    deps_json_file = os.path.join(config['temp_dir'], 'deps.json')
    os.system(f"conan info {config['project_path']} --paths  --json {deps_json_file}  ")
    deps_data = json.load(open(deps_json_file))
    output_json = [x for x in deps_data if x.get('revision') is not None]  # filter items which have the revision tag
    return output_json


# 5. curl each file from each dependency / conanfile.py / conandata.yml
def download_source_files(json_data):
    packages_list = []
    counter = 0

    config['directory'] = os.path.join(config['temp_dir'], "temp_deps")
    os.mkdir(config['directory'])

    for item in json_data:
        export_folder = item.get('export_folder')

        if export_folder is not None:
            packages_list.append({item.get('reference').split('/')[0]: item.get('reference').split('/')[1]})
        temp = packages_list[counter]
        key = list(temp)[0]
        value = str(temp[key])
        package_directory = os.path.join(config['directory'], key + '-' + value)  # replace forward's '/' of with dash '-' as this is more similar to whitesource library names convention
        pathlib.Path(package_directory).mkdir(parents=True, exist_ok=True)

        dependency_source = os.path.join(export_folder, 'conandata.yml')  # Check for conandata.yml file
        if os.path.exists(dependency_source):
            download_and_extract_source(dependency_source, package_directory, packages_list[counter])

        elif os.path.exists(os.path.join(export_folder, 'conanfile.py')):  # get conandata.yml from conanfile.py
            os.system(f"conan source --source-folder {package_directory} --install-folder {config['temp_dir']} {export_folder}")
            download_and_extract_source(package_directory, package_directory, packages_list[counter])

        else:
            logging.warning(f"{packages_list[counter]} source files were not found")
        counter += 1

    return packages_list


def download_and_extract_source(source, directory, package_name):
    try:
        a_yaml_file = open(source)
        parsed_yaml_file = yaml.load(a_yaml_file, Loader=yaml.FullLoader)
        temp = parsed_yaml_file['sources']
        for key, value in temp.items():
            url = value['url']
            if isinstance(url, list):  # for cases when the yml file has url with multiple links --> we will take the 1st in order
                url = url[0]
            r = requests.get(url, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
            open(os.path.join(directory, os.path.basename(url)), 'wb').write(r.content)
    except (FileNotFoundError, PermissionError):
        logging.error(f"Could not download source files for {package_name} as conandata.yml was not found")


# 7.scan project and list all source files from the scan.
def scan_with_unified_agent():
    unified_agent = ws_sdk.WSClient(user_key=config['user_key'], token=config['org_token'], url=config['ws_url'], ua_path=config['project_path'])
    unified_agent.ua_conf.productName = config['product_name']
    unified_agent.ua_conf.productToken = config['product_token']
    unified_agent.ua_conf.projectName = config['project_name']
    unified_agent.ua_conf.projectToken = config['project_token']
    unified_agent.ua_conf.includes = '**/*.*'
    unified_agent.ua_conf.archiveExtractionDepth = str(ws_constants.UAArchiveFiles.ARCHIVE_EXTRACTION_DEPTH_MAX)
    unified_agent.ua_conf.archiveIncludes = list(ws_constants.UAArchiveFiles.ALL_ARCHIVE_FILES)
    logging.getLogger().setLevel(logging.DEBUG)  # Instead of debug log level for the entire script
    support_token = unified_agent.scan(scan_dir=config['directory'],product_name=unified_agent.ua_conf.productName,product_token=unified_agent.ua_conf.productToken,project_name=unified_agent.ua_conf.projectName,project_token=unified_agent.ua_conf.projectToken)

    support_token = support_token[1].split('\n')  # list the scan log
    for line in support_token:
        if re.search('Support Token:', line):
            line = list(line.split(" "))
            support_token = line[7].rstrip()
            break
    logging.getLogger().setLevel(logging.INFO)

    scan_status = True
    while scan_status:
        new_status = get_scan_status(support_token)['requestState']
        if new_status in ['UPDATED', 'FINISHED']:
            logging.info('scan upload completed')
            scan_status = False
        elif new_status in ['UNKNOWN', 'FAILED']:
            logging.warning('scan failed to upload...exiting program')
            sys.exit(1)
        else:
            logging.info('scan result is being uploaded...')
            time.sleep(10.0)


def get_scan_status(support_token):
    status = ws_conn.call_ws_api(get_request_state, {ORG_TOKEN: config['org_token'], 'requestToken': support_token})
    logging.info(status['requestState'])  # for Debugging
    return status


# 8.change source files to a library per 3-4 ( API - changeOriginLibrary)
def match_project_source_file_inventory(packages):
    project_source_files_inventory = ws_conn.call_ws_api(get_project_source_file_inventory_report, {PROJECT_TOKEN: config['project_token'], 'format': 'json'})
    packages_and_source_files_sha1 = defaultdict(list)
    for package in packages:
        package_name = list(package.keys())[0]
        package_full_name = package_name + '-' + package[package_name]

        for source_file in project_source_files_inventory:
            if package_full_name in source_file['path']:
                packages_and_source_files_sha1[json.dumps(package)].append(source_file['sha1'])

    counter = 0

    for package, sha1s in packages_and_source_files_sha1.items():
        package = json.loads(package)
        library_name = list(package.keys())[0]
        library_version = package[library_name]
        library_search_result = ws_conn.call_ws_api(library_search, {'searchValue': library_name})
        no_match = True
        for library in library_search_result['libraries']:
            if library['type'] == 'Source Library':

                if library_name == library['artifactId']:
                    no_match = compare_library_version(packages, library_version, library['version'], library['keyUuid'], packages_and_source_files_sha1[json.dumps(package)], package, counter, sha1s, library['filename'])
                    counter_new = no_match[1]
                    if no_match[0] is False:
                        no_match = False
                        counter = counter_new
                        break

        if no_match:
            logging.info(f" Did not find match for {package} package source files.")


def compare_library_version(packages, package_library_version, library_search_version, library_key_uuid, source_files, package, counter, sha1s, matched_library_name):
    if package_library_version == library_search_version:
        no_match = False
        counter += 1

        ws_conn.call_ws_api(change_origin_library, {'targetKeyUuid': library_key_uuid, 'sourceFiles': source_files, 'userComments': 'Source files changed by Whitesource conan scan'})
        logging.info(f"--{counter}/{len(packages)} libraries were matched ( {package} source files in package: {len(sha1s)} were matched to {matched_library_name} )  ")
        return no_match, counter

    else:
        no_match = True
        counter = 0
        return no_match, counter


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 'True', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'False', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def get_args(arguments) -> dict:
    """Get configuration arguments"""

    logging.info('Start analyzing arguments.')
    parser = argparse.ArgumentParser(description='argument parser')

    parser.add_argument('-c', '--configFile', help='The config file', required=False, dest='conf_f')
    is_config_file = bool(arguments[0] in ['-c', '--configFile'])

    parser.add_argument('-d', "--" + PROJECT_PATH, help=f"The directory which contains the {CONAN_FILE_TXT} path", type=Path, required=not is_config_file, dest='project_path')
    parser.add_argument('-if', "--" + CONAN_INSTALL_FOLDER, help=f"The folder in which the installation of packages outputs the generator files with the information of dependencies.", type=Path, required=not is_config_file, dest='conan_install_folder', default=config['temp_dir'])
    parser.add_argument('-s', "--" + KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN, help="keep the install folder after run", dest='keep_conan_install_folder_after_run', required=not is_config_file, default=KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN_DEFAULT_VALUE, type=str2bool)
    parser.add_argument('-g', "--" + FIND_MATCH_FOR_REFERENCE, help="True will attempt to match libraries per package name and version", dest='find_match_for_reference', required=not is_config_file, default=FIND_MATCH_FOR_REFERENCE_DEFAULTE_VALUE, type=str2bool)
    parser.add_argument('-u', '--' + WS_URL, help='The organization url', required=not is_config_file, dest='ws_url')
    parser.add_argument('-k', '--' + USER_KEY, help='The admin user key', required=not is_config_file, dest='user_key')
    parser.add_argument('-t', '--' + ORG_TOKEN, help='The organization token', required=not is_config_file, dest='org_token')
    parser.add_argument('--' + PRODUCT_TOKEN, help='The product token', required=not is_config_file, dest='product_token')
    parser.add_argument('--' + PROJECT_TOKEN, help='The project token', required=not is_config_file, dest='project_token')
    parser.add_argument('--' + PRODUCT_NAME, help='The product name', required=not is_config_file, dest='product_name')
    parser.add_argument('--' + PROJECT_NAME, help='The project name', required=not is_config_file, dest='project_name')
    parser.add_argument('-m', '--' + PROJECT_PARALLELISM_LEVEL, help='The number of threads to run with', required=not is_config_file, dest='project_parallelism_level', type=int, default=PROJECT_PARALLELISM_LEVEL_DEFAULT_VALUE, choices=PROJECT_PARALLELISM_LEVEL_RANGE)

    args = parser.parse_args()

    if args.conf_f is None:
        args_dict = vars(args)
        args_dict.update(get_config_parameters_from_environment_variables())

    elif os.path.exists(args.conf_f):
        logging.info(f'Using {args.conf_f} , additional arguments from the CLI will be ignored')
        args_dict = get_config_file(args.conf_f)
    else:
        logging.error("Config file doesn't exists")
        sys.exit(1)

    logging.info('Finished analyzing arguments.')
    return args_dict


def get_config_file(config_file) -> dict:
    conf_file = ConfigParser()
    conf_file.read(config_file)

    logging.info('Start analyzing config file.')
    conf_file_dict = {
        'project_path': conf_file[CONFIG_FILE_HEADER_NAME].get(PROJECT_PATH),
        'conan_install_folder': conf_file[CONFIG_FILE_HEADER_NAME].get(CONAN_INSTALL_FOLDER),
        'keep_conan_install_folder_after_run': conf_file[CONFIG_FILE_HEADER_NAME].getboolean(KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN, fallback=KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN_DEFAULT_VALUE),
        'find_match_for_reference': conf_file[CONFIG_FILE_HEADER_NAME].getboolean(FIND_MATCH_FOR_REFERENCE, fallback=FIND_MATCH_FOR_REFERENCE_DEFAULTE_VALUE),
        'ws_url': conf_file[CONFIG_FILE_HEADER_NAME].get(WS_URL),
        'user_key': conf_file[CONFIG_FILE_HEADER_NAME].get(USER_KEY),
        'org_token': conf_file[CONFIG_FILE_HEADER_NAME].get(ORG_TOKEN),
        'product_token': conf_file[CONFIG_FILE_HEADER_NAME].get(PRODUCT_TOKEN),
        'project_token': conf_file[CONFIG_FILE_HEADER_NAME].get(PROJECT_TOKEN),
        'product_name': conf_file[CONFIG_FILE_HEADER_NAME].get(PRODUCT_NAME),
        'project_name': conf_file[CONFIG_FILE_HEADER_NAME].get(PROJECT_NAME),
        'project_parallelism_level': conf_file[CONFIG_FILE_HEADER_NAME].getint(PROJECT_PARALLELISM_LEVEL, fallback=PROJECT_PARALLELISM_LEVEL_DEFAULT_VALUE)
    }

    check_if_config_project_parallelism_level_is_valid(conf_file_dict['project_parallelism_level'])

    conf_file_dict.update(get_config_parameters_from_environment_variables())

    for key, value in conf_file_dict.items():
        if value is None:
            logging.error(f'Please check your {key} parameter-it is missing from the config file')
            sys.exit(1)

    logging.info('Finished analyzing the config file.')

    return conf_file_dict


def get_config_parameters_from_environment_variables() -> dict:
    os_env_variables = dict(os.environ)
    ws_env_vars_dict = {}
    for variable in WS_ENV_VARS:
        if variable in os_env_variables:
            logging.info(f'found {variable} environment variable - will use its value')
            ws_env_vars_dict[variable[len(WS_PREFIX):].lower()] = os_env_variables[variable]
            if variable == 'WS_FIND_MATCH_FOR_REFERENCE':
                ws_env_vars_dict.update({'find_match_for_reference': str2bool(ws_env_vars_dict['find_match_for_reference'])})  # to assign boolean instead of string
            if variable == 'WS_PROJECT_PARALLELISM_LEVEL':
                check_if_config_project_parallelism_level_is_valid(ws_env_vars_dict['project_parallelism_level'])

    return ws_env_vars_dict


def check_if_config_project_parallelism_level_is_valid(parallelism_level):
    if int(parallelism_level) not in PROJECT_PARALLELISM_LEVEL_RANGE:
        logging.error(f'The selected {PROJECT_PARALLELISM_LEVEL} <{parallelism_level}> is not valid')
        sys.exit(1)


def read_setup():
    """reads the configuration from cli / config file and updates in a global config."""

    global config, ws_conn
    args = sys.argv[1:]
    if len(args) > 0:
        config = get_args(args)
    elif os.path.isfile(DEFAULT_CONFIG_FILE):  # used mainly when running the script from an IDE -> same path of CONFIG_FILE (params.config)
        config = get_config_file(DEFAULT_CONFIG_FILE)
    else:
        config = get_config_parameters_from_environment_variables()

    ws_conn = WS(url=config['ws_url'],
                 user_key=config['user_key'],
                 token=config['org_token'],
                 tool_details=(f"ps-{__tool_name__.replace('_', '-')}", __version__),
                 timeout=3600)


def main():
    read_setup()

    start_time = datetime.now()
    logging.info(f"Start running {__description__} on token {config['org_token']}. Parallelism level: {config['project_parallelism_level']}")

    validate_conan_local_cache_folder()
    validate_project_manifest_file_exists()
    run_conan_install_command()
    dependencies_list = list_all_dependencies()
    packages = download_source_files(dependencies_list)
    scan_with_unified_agent()

    config['find_match_for_reference'] = False  # Todo - remove once TKA-2886 is fixed
    if config['find_match_for_reference']:
        match_project_source_file_inventory(packages)

    logging.info(f"Finished running {__description__}. Run time: {datetime.now() - start_time}")
    if not config['keep_conan_install_folder_after_run']:
        try:
            shutil.rmtree(config['temp_dir'])
            logging.info(f"removed conanInstallFolder : {config['temp_dir']}")
        except OSError as e:
            logging.error("Error: %s - %s." % (e.filename, e.strerror))


if __name__ == '__main__':
    main()
