import argparse
import json
import logging
import os
import pathlib
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
from ws_sdk import *
from ws_sdk.ws_utilities import convert_dict_list_to_dict

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
USER_KEY = 'userKey'
PROJECT_TOKEN = 'projectToken'
PRODUCT_TOKEN = 'productToken'
PROJECT_NAME = 'projectName'
PRODUCT_NAME = 'productName'
ORG_TOKEN = 'orgToken'
PROJECT_PATH = 'projectPath'
UNIFIED_AGENT_PATH = 'unifiedAgentPath'
CONAN_INSTALL_FOLDER = 'conanInstallFolder'
KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN = 'keepConanInstallFolderAfterRun'
KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN_DEFAULT = False
FIND_MATCH_FOR_REFERENCE = 'findMatchForReference'
FIND_MATCH_FOR_REFERENCE_DEFAULT = False
CONAN_RUN_PRE_STEP = 'conanRunPreStep'
CONAN_RUN_PRE_STEP_DEFAULT = False
WS_URL = 'wsUrl'
config = dict()
conan_profile = dict()
ws_conn = ''
PROJECT_PARALLELISM_LEVEL = 'projectParallelismLevel'
PROJECT_PARALLELISM_LEVEL_MAX_VALUE = 20
PROJECT_PARALLELISM_LEVEL_DEFAULT_VALUE = 9
PROJECT_PARALLELISM_LEVEL_RANGE = list(range(1, PROJECT_PARALLELISM_LEVEL_MAX_VALUE + 1))

CONAN_FILE_TXT = 'conanfile.txt'
CONAN_FILE_PY = 'conanfile.py'


def validate_conan_installed():
    """ Validate conan is installed by retrieving the Conan home directory"""
    conan_version = subprocess.Popen("conan --version", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    converted_list = []

    for element in conan_version:
        if '\n' in element:
            break
        else:
            converted_list.append(element)
    conan_version = ''.join(converted_list)
    if 'Conan version' in conan_version:
        logging.info(f"Conan identified - {conan_version} ")
    else:
        logging.error(f"Please check conan is installed and configured properly ")
        sys.exit(1)


def map_conan_profile_values():
    profile = {}

    profile['os'] = subprocess.Popen("conan profile get settings.os default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    profile['os_build'] = subprocess.Popen("conan profile get settings.os_build default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    profile['arch'] = subprocess.Popen("conan profile get settings.arch default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    profile['arch_build'] = subprocess.Popen("conan profile get settings.arch_build default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    profile['compiler'] = subprocess.Popen("conan profile get settings.compiler default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    profile['compiler.runtime'] = subprocess.Popen("conan profile get settings.compiler.runtime default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    profile['compiler.version'] = subprocess.Popen("conan profile get settings.compiler.version default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    profile['build_type'] = subprocess.Popen("conan profile get settings.build_type default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]

    for k, v in profile.items():
        profile[k] = ''.join(v.partition('\n')[0:1])
    return profile


def validate_project_manifest_file_exists():
    logging.info(f"Checking for conanfile.")

    if os.path.exists(os.path.join(config['project_path'], CONAN_FILE_TXT)):
        logging.info(f"The {CONAN_FILE_TXT} manifest file exists in your environment.")
    elif os.path.exists(os.path.join(config['project_path'], CONAN_FILE_PY)):
        logging.info(f"The {CONAN_FILE_PY} manifest file exists in your environment.")
    else:
        logging.error(f"A supported manifest file was not found in {config['project_path']}.")
        sys.exit(1)


def map_all_dependencies():
    """
    Function to list all dependencies with: conan info DIR_CONTAINING_CONANFILE --paths --dry-build --json TEMP_JSON_PATH
    :return:list
    """
    deps_json_file = os.path.join(config['temp_dir'], 'deps.json')
    os.system(f"conan info {config['project_path']} --paths --dry-build  --json {deps_json_file}  ")
    with open(deps_json_file, encoding='utf-8') as f:
        deps_data = json.load(f)
    output_json = [x for x in deps_data if x.get('revision') is not None]  # filter items which have the revision tag
    return output_json


def run_conan_install_command():
    """ Allocate the scanned project dependencies in the conanInstallFolder"""
    try:
        subprocess.run(f"conan install {config['project_path']} --install-folder {config['temp_dir']} --build", shell=True, stdout=subprocess.PIPE, text=True)
        logging.info(f"conan install --build completed , install folder : {config['temp_dir']}")
    except subprocess.CalledProcessError as e:
        logging.error("Error: %s - %s." % (e.filename, e.strerror))


def conan_cache_packges_source_folder_missing(dependcies_list: list):
    missing_source = []
    for item in dependcies_list:
        if os.path.exists(item.get('source_folder')):
            logging.info(f"Source folder exists for {item.get('reference')} at: {item.get('source_folder')}")
        else:
            logging.warning(f"Source folder missing for {item.get('reference')} at: {item.get('source_folder')}")
            missing_source.append(item.get('reference'))
    return missing_source


def get_dependencies_from_download_source(missing_packages, dependencies_list) -> list:
    """Download each dependency source files / archive to conanInstallFolder/YmdHMSf/package_name-package_version and returns a list of names/versions
    :return: a list dictionaries {'package_name:package_version'}
    :rtype: list
    """
    dependencies_list_dict = ws_utilities.convert_dict_list_to_dict(lst=dependencies_list, key_desc='reference')
    packages_list = []
    counter = 0

    for item in missing_packages:
        export_folder = dependencies_list_dict[item]['export_folder']
        package_directory = os.path.join(config['directory'], item.split('/')[0] + '-' + item.split('/')[1])  # replace  '/' with '-' to align with whitesource convention .
        pathlib.Path(package_directory).mkdir(parents=True, exist_ok=True)

        dependency_conan_data_yml = os.path.join(export_folder, 'conandata.yml')  # Check for conandata.yml file
        if os.path.isfile(dependency_conan_data_yml):
            packages_list.append(package_directory)
            download_source_package(dependency_conan_data_yml, package_directory, missing_packages[counter])

        elif os.path.isfile(os.path.join(export_folder, 'conanfile.py')):  # creates conandata.yml from conanfile.py
            logging.info(f"{missing_packages[counter]} conandata.yml is missing from {export_folder} - will try to get with conan source command")
            p = subprocess.Popen(f"conan source --source-folder {package_directory} --install-folder {package_directory} {export_folder}", shell=True, stdout=subprocess.PIPE, text=True)
            logging.info(p.communicate()[0])
            packages_list.append(package_directory)
            download_source_package(package_directory, package_directory, missing_packages[counter])

        # if os.path.isfile(os.path.join(export_folder, 'conanfile.py')):#Todo - consider working only with this option -might conflict with find_match_for_reference which rely on conandata.yml
        #     os.system(f"conan install {os.path.join(export_folder, 'conanfile.py')} {item.split('/')[1]}@ --install-folder {package_directory} ")
        #     os.system(f"conan source --source-folder {package_directory} --install-folder {package_directory} {os.path.join(export_folder, 'conanfile.py')}  ")
        #     packages_list.append(package_directory)

        else:
            logging.warning(f"{packages_list[counter]} source files were not found")
        counter += 1

    return packages_list


def download_source_package(source, directory, package_name):
    try:
        url = extract_url_from_conan_data_yml(source, package_name)
        if url:
            r = requests.get(url, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
            with open(os.path.join(directory, os.path.basename(url)), 'wb') as b:
                b.write(r.content)
                logging.info(f"{package_name} source files were retrieved from {source} and saved at {directory} ")
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        logging.warning(f"Could not download source files for {package_name} as conandata.yml was not found")


def get_source_folders_list(dependcies_list: list, is_sf_missing):
    source_folder_list = []
    for item in dependcies_list:
        if item.get('reference') not in is_sf_missing:
            source_folder_list.append(item.get('source_folder'))
    return source_folder_list


def scan_with_unified_agent(source_dirs_to_scan):
    unified_agent = ws_sdk.WSClient(user_key=config['user_key'], token=config['org_token'], url=config['ws_url'], ua_path=config['unified_agent_path'])
    unified_agent.ua_conf.productName = config['product_name']
    unified_agent.ua_conf.productToken = config['product_token']
    unified_agent.ua_conf.projectName = config['project_name']
    unified_agent.ua_conf.projectToken = config['project_token']
    unified_agent.ua_conf.resolveAllDependencies = str(False)
    unified_agent.ua_conf.includes = '**/*.*'
    unified_agent.ua_conf.archiveExtractionDepth = str(ws_constants.UAArchiveFiles.ARCHIVE_EXTRACTION_DEPTH_MAX)
    unified_agent.ua_conf.archiveIncludes = list(ws_constants.UAArchiveFiles.ALL_ARCHIVE_FILES)
    unified_agent.ua_conf.logLevel = 'debug'
    # unified_agent.ua_conf.scanPackageManager = True #Todo - check for support in favor of https://docs.conan.io/en/latest/reference/conanfile/methods.html?highlight=system_requirements#system-requirements

    output = unified_agent.scan(scan_dir=source_dirs_to_scan, product_name=unified_agent.ua_conf.productName, product_token=unified_agent.ua_conf.productToken, project_name=unified_agent.ua_conf.projectName, project_token=unified_agent.ua_conf.projectToken)
    logging.info(output[1])
    support_token = output[2]  # gets Support Token from scan output

    scan_status = True
    while scan_status:
        new_status = ws_conn.get_last_scan_process_status(support_token)
        logging.info(f"Scan Status :{new_status}")
        if new_status in ['UPDATED', 'FINISHED']:
            logging.info('scan upload completed')
            scan_status = False
        elif new_status in ['UNKNOWN', 'FAILED']:
            logging.warning('scan failed to upload...exiting program')
            sys.exit(1)
        else:
            time.sleep(10.0)


def change_project_source_file_inventory_match(packages):
    """changes source files mapping with changeOriginLibrary API"""
    if not config['project_token']:
        project_token = ws_conn.get_tokens_from_name(config['project_name'], token_type='project')[0]
        # project_token=ws_conn.get_scopes_from_name(config['project_name'], token_type='project') #Todo switch to this as get_tokens_from_name might return two tokens for projects with the same name
    else:
        project_token = config['project_token']

    # Filtering on project's source libraries download link compared with url from conandata.yml --> if it's the same , ws source files matching was correct and no need to change.

    project_due_diligence = ws_conn.get_due_diligence(token=project_token, report=False)
    for library in project_due_diligence:
        if library['library'][len(library['library']) - 1] == '*':  # Remove astrix from the end of library name (occurs when licences number >1 )
            library['library'] = library['library'][:-1]
    project_due_diligence_dict = convert_dict_list_to_dict(project_due_diligence, key_desc='library')

    for package in packages:
        source = os.path.join(package['export_folder'], 'conandata.yml')
        url = extract_url_from_conan_data_yml(source, package)
        package.update({'conandata_yml_download_url': url})

    packages_dict_by_download_link = convert_dict_list_to_dict(lst=packages, key_desc='conandata_yml_download_url')

    project_source_files_inventory = ws_conn.get_source_file_inventory(report=False, token=project_token)

    for source_file in project_source_files_inventory:
        source_file['source_lib_full_name'] = source_file['library']['artifactId'] + '-' + source_file['library']['version']
        source_file['download_link'] = project_due_diligence_dict[source_file['source_lib_full_name']].get('download_link')

        if packages_dict_by_download_link.get(source_file['download_link']):
            # logging.info(f"removing {source_file['source_lib_full_name']}-{source_file['filename']}-{source_file['sha1']}")
            project_source_files_inventory.remove(source_file)

    packages_and_source_files_sha1 = get_packages_source_files_from_inventory_scan_results(project_source_files_inventory, packages)

    ##########################################
    counter = 0

    packages_dict_by_package_name = convert_dict_list_to_dict(lst=packages, key_desc='package_name')

    for package, sha1s in packages_and_source_files_sha1.items():  # Todo - add threads
        package = json.loads(package)
        library_name = package.partition('-')[0]
        library_search_result = ws_conn.get_libraries(library_name)

        source_libraries = []
        for library in library_search_result:
            if library['type'] == 'Source Library':
                source_libraries.append(library)

        check_url = packages_dict_by_package_name[package]['conandata_yml_download_url']
        source_libraries_dict = convert_dict_list_to_dict(source_libraries, key_desc=str('url'))

        if source_libraries_dict.get(check_url):
            library_key_uuid = source_libraries_dict[check_url].get('keyUuid')
            ws_conn.call_ws_api('changeOriginLibrary', {'targetKeyUuid': library_key_uuid, 'sourceFiles': sha1s, 'userComments': 'Source files changed by Whitesource conan scan'})
            no_match = False
            counter += 1
            logging.info(f"--{counter}/{len(packages)} libraries were matched ( {len(sha1s)} source files in {package} package:  were matched to {source_libraries_dict[check_url]['filename']} source library )")

        else:
            no_match = True
            counter = 0

        if no_match:
            logging.info(f" Did not find match for {package} package source files.")


def get_packages_source_files_from_inventory_scan_results(project_source_files_inventory, packages):
    packages_and_source_files_sha1 = defaultdict(list)
    for package in packages:
        package.update({'package_name': package['reference'].replace('/', '-')})

        for source_file in project_source_files_inventory:
            if package['package_name'] in source_file['path'] or package['source_folder'] in source_file['path']:
                packages_and_source_files_sha1[json.dumps(package['package_name'])].append(source_file['sha1'])
    return packages_and_source_files_sha1


def extract_url_from_conan_data_yml(source, package):
    #  https://github.com/conan-io/hooks/pull/269 , https://github.com/jgsogo/conan-center-index/blob/policy/patching-update/docs/conandata_yml_format.md
    try:
        with open(source) as a_yaml_file:
            parsed_yaml_file = yaml.load(a_yaml_file, Loader=yaml.FullLoader)
        temp = parsed_yaml_file['sources']
        for key, value in temp.items():
            url = value.get('url')
            if isinstance(url, dict) and url.get(conan_profile['os_build']):
                url = url.get(conan_profile['os_build'])
            if isinstance(url, dict) and url.get(conan_profile['arch_build']):
                url = url.get(conan_profile['arch_build'])
            if isinstance(url, list):
                url = url[0]
            return url
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        logging.warning(f"Could not find {str(package)} conandata.yml file")


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

    parser.add_argument('-d', "--" + PROJECT_PATH, help=f"The directory which contains the conanfile.txt / conanfile.py path", type=Path, required=not is_config_file, dest='project_path')
    parser.add_argument('-a', "--" + UNIFIED_AGENT_PATH, help=f"The directory which contains the Unified Agent", type=Path, required=not is_config_file, dest='unified_agent_path')
    parser.add_argument('-if', "--" + CONAN_INSTALL_FOLDER, help=f"The folder in which the installation of packages outputs the generator files with the information of dependencies. Format: %Y%m%d%H%M%S%f", type=Path, required=not is_config_file, dest='conan_install_folder')
    parser.add_argument('-s', "--" + KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN, help="keep the install folder after run", dest='keep_conan_install_folder_after_run', required=not is_config_file, default=KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN_DEFAULT, type=str2bool)
    parser.add_argument('-p', "--" + CONAN_RUN_PRE_STEP, help="run conan install --build", dest='conan_run_pre_step', required=not is_config_file, default=CONAN_RUN_PRE_STEP_DEFAULT, type=str2bool)
    # parser.add_argument('-g', "--" + FIND_MATCH_FOR_REFERENCE, help="True will attempt to match libraries per package name and version", dest='find_match_for_reference', required=not is_config_file, default=FIND_MATCH_FOR_REFERENCE_DEFAULT, type=str2bool)  # Todo - uncomment once WIN-1906 is done
    parser.add_argument('-u', '--' + WS_URL, help='The WhiteSource organization url', required=not is_config_file, dest='ws_url')
    parser.add_argument('-k', '--' + USER_KEY, help='The admin user key', required=not is_config_file, dest='user_key')
    parser.add_argument('-t', '--' + ORG_TOKEN, help='The organization token', required=not is_config_file, dest='org_token')
    parser.add_argument('--' + PRODUCT_TOKEN, help='The product token', required=not is_config_file, dest='product_token')
    parser.add_argument('--' + PROJECT_TOKEN, help='The project token', required=not is_config_file, dest='project_token')
    parser.add_argument('--' + PRODUCT_NAME, help='The product name', required=not is_config_file, dest='product_name')
    parser.add_argument('--' + PROJECT_NAME, help='The project name', required=not is_config_file, dest='project_name')
    # parser.add_argument('-m', '--' + PROJECT_PARALLELISM_LEVEL, help='The number of threads to run with', required=not is_config_file, dest='project_parallelism_level', type=int, default=PROJECT_PARALLELISM_LEVEL_DEFAULT, choices=PROJECT_PARALLELISM_LEVEL_RANGE)

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
        'unified_agent_path': conf_file[CONFIG_FILE_HEADER_NAME].get(UNIFIED_AGENT_PATH),
        'conan_install_folder': conf_file[CONFIG_FILE_HEADER_NAME].get(CONAN_INSTALL_FOLDER),
        'keep_conan_install_folder_after_run': conf_file[CONFIG_FILE_HEADER_NAME].getboolean(KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN, fallback=KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN_DEFAULT),
        'conan_run_pre_step': conf_file[CONFIG_FILE_HEADER_NAME].getboolean(CONAN_RUN_PRE_STEP, fallback=CONAN_RUN_PRE_STEP_DEFAULT),
        # 'find_match_for_reference': conf_file[CONFIG_FILE_HEADER_NAME].getboolean(FIND_MATCH_FOR_REFERENCE, fallback=FIND_MATCH_FOR_REFERENCE_DEFAULT),  # Todo - uncomment once WIN-1906 is done
        'ws_url': conf_file[CONFIG_FILE_HEADER_NAME].get(WS_URL),
        'user_key': conf_file[CONFIG_FILE_HEADER_NAME].get(USER_KEY),
        'org_token': conf_file[CONFIG_FILE_HEADER_NAME].get(ORG_TOKEN),
        'product_token': conf_file[CONFIG_FILE_HEADER_NAME].get(PRODUCT_TOKEN),
        'project_token': conf_file[CONFIG_FILE_HEADER_NAME].get(PROJECT_TOKEN),
        'product_name': conf_file[CONFIG_FILE_HEADER_NAME].get(PRODUCT_NAME),
        'project_name': conf_file[CONFIG_FILE_HEADER_NAME].get(PROJECT_NAME),
        # 'project_parallelism_level': conf_file[CONFIG_FILE_HEADER_NAME].getint(PROJECT_PARALLELISM_LEVEL, fallback=PROJECT_PARALLELISM_LEVEL_DEFAULT_VALUE)
    }

    # check_if_config_project_parallelism_level_is_valid(conf_file_dict['project_parallelism_level'])

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
            # if variable == 'WS_PROJECT_PARALLELISM_LEVEL':
            #     check_if_config_project_parallelism_level_is_valid(ws_env_vars_dict['project_parallelism_level'])

    return ws_env_vars_dict


# def check_if_config_project_parallelism_level_is_valid(parallelism_level):
#     if int(parallelism_level) not in PROJECT_PARALLELISM_LEVEL_RANGE:
#         logging.error(f'The selected {PROJECT_PARALLELISM_LEVEL} <{parallelism_level}> is not valid')
#         sys.exit(1)


def create_configuration():
    """reads the configuration from cli / config file and updates in a global config."""

    global config, ws_conn
    args = sys.argv[1:]
    if len(args) > 0:
        config = get_args(args)
    elif os.path.isfile(DEFAULT_CONFIG_FILE):  # used mainly when running the script from an IDE -> same path of CONFIG_FILE (params.config)
        config = get_config_file(DEFAULT_CONFIG_FILE)
    else:
        config = get_config_parameters_from_environment_variables()

    # Set configuration for temp directory location which will contain dependencies source files.
    if not config['conan_install_folder']:
        config['temp_dir'] = Path(config['project_path'], datetime.now().strftime('%Y%m%d%H%M%S%f'))
    elif os.path.exists(config['conan_install_folder']):
        config['temp_dir'] = Path(config['conan_install_folder'], datetime.now().strftime('%Y%m%d%H%M%S%f'))
    else:
        logging.error(f"Please validate the conan install folder exists")
        sys.exit(1)

    # Set configuration for Unified Agent directory location
    if not config['unified_agent_path']:
        config['unified_agent_path'] = config['project_path']

    # Set connection for API calls
    ws_conn = WS(url=config['ws_url'],
                 user_key=config['user_key'],
                 token=config['org_token'],
                 tool_details=(f"ps-{__tool_name__.replace('_', '-')}", __version__))


def main():
    global conan_profile

    create_configuration()

    start_time = datetime.now()
    logging.info(f"Start running {__description__} on token {config['org_token']}.")
    validate_conan_installed()
    conan_profile = map_conan_profile_values()
    validate_project_manifest_file_exists()

    if config['conan_run_pre_step']:
        logging.info(f"conanRunPreStep is set to {config['conan_run_pre_step']} - will run 'conan install --build' command.")
        run_conan_install_command()

    dependencies_list = map_all_dependencies()

    dirs_to_scan = []
    source_folders_missing = conan_cache_packges_source_folder_missing(dependencies_list)

    if source_folders_missing:
        config['directory'] = os.path.join(config['temp_dir'], "temp_deps")
        os.mkdir(config['directory'])
        temp = '\n'.join(source_folders_missing)
        logging.info(f"The following packages source files are missing from the conan cache - will try to extract via conandata.yml files to {config['directory']} :\n{temp}")
        source_from_conandata_yml = get_dependencies_from_download_source(source_folders_missing, dependencies_list)
        dirs_to_scan.append(source_from_conandata_yml)

    source_from_conan_cache = get_source_folders_list(dependencies_list, source_folders_missing)
    dirs_to_scan.append(source_from_conan_cache)
    dirs_to_scan_joined_list = [x for l in dirs_to_scan for x in l]
    scan_with_unified_agent(dirs_to_scan_joined_list)

    # if config['find_match_for_reference']:
    #     change_project_source_file_inventory_match(dependencies_list)  # Todo - uncomment once WIN-1906 is done and remove config['find_match_for_reference']=True

    logging.info(f"Finished running {__description__}. Run time: {datetime.now() - start_time}")
    if not config['keep_conan_install_folder_after_run']:
        try:
            shutil.rmtree(config['temp_dir'])
            logging.info(f"removed conanInstallFolder : {config['temp_dir']}")
        except OSError as e:
            logging.error("Error: %s - %s." % (e.filename, e.strerror))

    # subprocess.run(f"conan remove * -s -b -f", shell=True, stdout=subprocess.PIPE, text=True)  # Todo add source+build remove after scan


if __name__ == '__main__':
    main()
