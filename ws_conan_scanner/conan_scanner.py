import argparse
import csv
import gc
import io
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import requests
import urllib3
import ws_sdk
import yaml
from ws_sdk.ws_constants import UAArchiveFiles
# from ws_sdk import *
from ws_sdk.ws_utilities import convert_dict_list_to_dict

from ws_conan_scanner._version import __tool_name__, __version__, __description__

logging.basicConfig(level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
                    handlers=[logging.StreamHandler(stream=sys.stdout)],
                    format='%(levelname)s %(asctime)s %(thread)d %(name)s: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')

# Config file variables
DEFAULT_CONFIG_FILE = 'params.config'
CONFIG_FILE_HEADER_NAME = 'DEFAULT'

# Environment variables
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
CHANGE_ORIGIN_LIBRARY = 'changeOriginLibrary'
CHANGE_ORIGIN_LIBRARY_DEFAULT = True
CONAN_RUN_PRE_STEP = 'conanRunPreStep'
CONAN_RUN_PRE_STEP_DEFAULT = False
INCLUDE_BUILD_REQUIRES_PACKAGES = 'includeBuildRequiresPackages'
INCLUDE_BUILD_REQUIRES_PACKAGES_DEFAULT = True
WS_URL = 'wsUrl'
conan_profile = dict()

PROJECT_PARALLELISM_LEVEL = 'projectParallelismLevel'
PROJECT_PARALLELISM_LEVEL_MAX_VALUE = 20
PROJECT_PARALLELISM_LEVEL_DEFAULT_VALUE = 9
PROJECT_PARALLELISM_LEVEL_RANGE = list(range(1, PROJECT_PARALLELISM_LEVEL_MAX_VALUE + 1))

CONAN_FILE_TXT = 'conanfile.txt'
CONAN_FILE_PY = 'conanfile.py'


class Config:
    def __init__(self, conf: dict):
        self.project_path = conf.get('project_path')
        self.unified_agent_path = conf.get('unified_agent_path')
        self.conan_install_folder = conf.get('conan_install_folder')
        self.keep_conan_install_folder_after_run = conf.get('keep_conan_install_folder_after_run')
        self.include_build_requires_packages = conf.get('include_build_requires_packages')
        self.conan_run_pre_step = conf.get('conan_run_pre_step')
        self.change_origin_library = conf.get('change_origin_library')
        self.ws_url = conf.get('ws_url')
        self.user_key = conf.get('user_key')
        self.org_token = conf.get('org_token')
        self.product_token = conf.get('product_token')
        self.project_token = conf.get('project_token')
        self.product_name = conf.get('product_name')
        self.project_name = conf.get('project_name')

        # Set configuration for temp directory location which will contain dependencies source files.
        self.date_time_now = datetime.now().strftime('%Y%m%d%H%M%S%f')
        self.temp_dir = Path(self.conan_install_folder, self.date_time_now)

        invalid_params = []

        if not os.path.exists(self.project_path):
            invalid_params.append({'projectPath': self.project_path})
            logging.error(f"Please validate that the projectPath path exists")

        if not os.path.exists(self.unified_agent_path):
            invalid_params.append({'unifiedAgentPath': self.unified_agent_path})
            logging.error(f"Please validate that the unifiedAgentPath path exists")

        if not os.path.exists(self.conan_install_folder):
            invalid_params.append({'conanInstallFolder': self.conan_install_folder})
            logging.error(f"Please validate that the conanInstallFolder path exists")

        # Set connection for API calls
        self.ws_conn = ws_sdk.web.WSApp(url=self.ws_url,
                                        user_key=self.user_key,
                                        token=self.org_token,
                                        tool_details=(f"ps-{__tool_name__.replace('_', '-')}", __version__), timeout=3600)

        logging.info(f"ws connections details:\nwsURL: {self.ws_url}\norgToken: {self.org_token}")
        self.ws_conn_details = self.ws_conn.get_organization_details()

        if len(invalid_params) > 0:
            logging.info(f"The following parameters should be fixed :\n{invalid_params}")
            sys.exit()


def validate_conan_installed():
    """ Validate conan is installed by retrieving the Conan home directory"""
    conan_version = subprocess.check_output(f"conan --version", shell=True, stderr=subprocess.STDOUT).decode()
    if 'Conan version' in conan_version:
        logging.info(f"Conan identified - {conan_version} ")
    else:
        logging.error(f"Please check Conan is installed and configured properly ")
        sys.exit(1)


def map_conan_profile_values():
    global conan_profile

    conan_profile = {
        'os': subprocess.Popen("conan profile get settings.os default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0],
        'os_build': subprocess.Popen("conan profile get settings.os_build default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0],
        'arch': subprocess.Popen("conan profile get settings.arch default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0],
        'arch_build': subprocess.Popen("conan profile get settings.arch_build default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0],
        'compiler': subprocess.Popen("conan profile get settings.compiler default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0],
        'compiler.runtime': subprocess.Popen("conan profile get settings.compiler.runtime default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0],
        'compiler.version': subprocess.Popen("conan profile get settings.compiler.version default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0],
        'build_type': subprocess.Popen("conan profile get settings.build_type default", shell=True, stdout=subprocess.PIPE, text=True).communicate()[0]
    }

    for k, v in conan_profile.items():
        conan_profile[k] = ''.join(v.partition('\n')[0:1])


def validate_project_manifest_file_exists(config):
    logging.info(f"Checking for conanfile.")

    if os.path.exists(os.path.join(config.project_path, CONAN_FILE_TXT)):
        logging.info(f"The {CONAN_FILE_TXT} manifest file exists in your environment.")
    elif os.path.exists(os.path.join(config.project_path, CONAN_FILE_PY)):
        logging.info(f"The {CONAN_FILE_PY} manifest file exists in your environment.")
    else:
        logging.error(f"A supported conanfile was not found in {config.project_path}.")
        sys.exit(1)


def map_all_dependencies(config):
    """
    Function to list all dependencies with: conan info DIR_CONTAINING_CONANFILE --paths --dry-build --json TEMP_JSON_PATH
    :return:list
    """
    try:
        deps_json_file = os.path.join(config.temp_dir, 'deps.json')
        logging.info(f"Mapping project's dependencies to {deps_json_file}")
        if config.include_build_requires_packages:
            output = subprocess.check_output(f"conan info {config.project_path} --paths --dry-build --json {deps_json_file}", shell=True, stderr=subprocess.STDOUT).decode()
        else:
            output = subprocess.check_output(f"conan info {config.project_path} --paths --json {deps_json_file}", shell=True, stderr=subprocess.STDOUT).decode()
        logging.info(f'\n{output}')  # Todo add print of deps.json

        with open(deps_json_file, encoding='utf-8') as f:
            deps_data = json.load(f)
        output_json = [x for x in deps_data if x.get('revision') is not None]  # filter items which have the revision tag
        return output_json
    except subprocess.CalledProcessError as e:
        logging.error(e.output.decode())
        logging.info("The conan scanner will stop due to a failure to")
        sys.exit(1)


def run_conan_install_command(config):
    """ Allocate the scanned project dependencies in the conanInstallFolder"""
    try:
        logging.info(f"conanRunPreStep is set to {config.conan_run_pre_step} - will run 'conan install --build' command.")
        output = subprocess.check_output(f"conan install {config.project_path} --install-folder {config.temp_dir} --build", shell=True, stderr=subprocess.STDOUT).decode()
        logging.info(output)
        logging.info(f"conan install --build completed , install folder : {config.temp_dir}")
    except subprocess.CalledProcessError as e:
        logging.error(e.output.decode())


def conan_cache_packages_source_folder_missing(conan_dependencies: list):
    missing_source = []
    for item in conan_dependencies:
        if os.path.exists(item.get('source_folder')):
            logging.info(f"Source folder exists for {item.get('reference')} at: {item.get('source_folder')}")
        else:
            logging.info(f"Source folder missing for {item.get('reference')} at: {item.get('source_folder')}")
            missing_source.append(item.get('reference'))
    return missing_source


def get_dependencies_from_download_source(config, source_folders_missing, conan_dependencies) -> list:
    """Download each dependency source files / archive to conanInstallFolder/YmdHMSf/package_name-package_version and returns a list of source files directories.
    :return: a list dictionaries {'package_name:package_version'}
    :rtype: list
    """
    config.directory = Path(config.temp_dir, "temp_deps")
    temp = '\n'.join(source_folders_missing)
    logging.info(f"The following packages source files are missing from the conan cache - will try to extract to {config.directory} :\n{temp}")
    dependencies_list_dict = convert_dict_list_to_dict(lst=conan_dependencies, key_desc='reference')

    packages_list = []

    for item in source_folders_missing:
        export_folder = dependencies_list_dict[item].get('export_folder')
        package_directory = os.path.join(config.directory, item.split('/')[0] + '-' + item.split('/')[1])  # replace  '/' with '-' to align with whitesource convention .
        pathlib.Path(package_directory).mkdir(parents=True, exist_ok=True)

        dependency_conan_data_yml = os.path.join(export_folder, 'conandata.yml')  # Check for conandata.yml file

        if os.path.isfile(os.path.join(export_folder, 'conanfile.py')):
            install_version = dependencies_list_dict.get(item).get('reference')
            if '@' not in install_version:
                install_version = install_version + '@'
            conan_install_command = f"conan install --install-folder {package_directory} {export_folder} {install_version}"
            conan_source_command = f"conan source --source-folder {package_directory} --install-folder {package_directory} {export_folder}"

            try:
                logging.info(f"Going to run the following command : {conan_install_command}")
                output = subprocess.check_output(conan_install_command, shell=True, stderr=subprocess.STDOUT).decode()
                logging.info(output)
                logging.info(f"Going to run the following command : {conan_source_command}")
                output = subprocess.check_output(conan_source_command, shell=True, stderr=subprocess.STDOUT).decode()
                logging.info(output)
                packages_list.append(package_directory)
                dependencies_list_dict.get(item)['conandata_yml'] = os.path.join(package_directory, 'conandata.yml')
            except subprocess.CalledProcessError as e:
                logging.error(e.output.decode())

                if os.path.isfile(os.path.join(package_directory, 'conandata.yml')):
                    logging.info(f"Will try to get source from {os.path.join(package_directory, 'conandata.yml')} ")
                    package_directory_returned = download_source_package(os.path.join(package_directory, 'conandata.yml'), package_directory, item)
                    packages_list.append(package_directory_returned)
                    dependencies_list_dict.get(item)['conandata_yml'] = os.path.join(package_directory, 'conandata.yml')

                elif os.path.isfile(dependency_conan_data_yml):
                    logging.info(f"Will try to get source from {dependency_conan_data_yml} ")
                    package_directory_returned = download_source_package(dependency_conan_data_yml, package_directory, item)
                    packages_list.append(package_directory_returned)
                    dependencies_list_dict.get(item)['conandata_yml'] = dependency_conan_data_yml

                elif os.path.isfile(os.path.join(export_folder, 'conanfile.py')):  # creates conandata.yml from conanfile.py
                    logging.info(f"{item} conandata.yml is missing from {export_folder} - will try to get with conan source command")
                    try:
                        logging.info(f"Going to run the following command : {conan_source_command}")
                        output = subprocess.check_output(conan_source_command, shell=True, stderr=subprocess.STDOUT).decode()
                        logging.info(output)
                        package_directory_returned = download_source_package(package_directory, package_directory, item)
                        packages_list.append(package_directory_returned)
                        dependencies_list_dict.get(item)['conandata_yml'] = os.path.join(package_directory, 'conandata.yml')
                    except subprocess.CalledProcessError as e:
                        logging.error(e.output.decode())

                else:
                    logging.warning(f"{item} source files were not found")

    return packages_list  # Todo remove


def download_source_package(source, directory, package_name):
    general_text = f"Could not download source files for {package_name}"
    try:
        url = extract_url_from_conan_data_yml(source, package_name)
        if url:
            r = requests.get(url, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
            with open(os.path.join(directory, os.path.basename(url)), 'wb') as b:
                b.write(r.content)
                logging.info(f"{package_name} source files were retrieved from {source} and saved at {directory} ")
                return directory
    except urllib3.exceptions.ProtocolError as e:
        logging.error(f'{general_text}\nGeneral requests error: ' + str(e.__traceback__))
    except requests.exceptions.ConnectionError as e:
        logging.error(f'{general_text}\nGeneral requests error: ' + e.response.text)
    except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
        logging.warning(f"{general_text} as conandata.yml was not found or is not accessible: " + e.response.text)
    except requests.exceptions.URLRequired as e:
        logging.error(f'{general_text}\nThe url retrieved from conandata.yml is missing: ' + e.response.text)
    except requests.exceptions.InvalidURL as e:
        logging.error(f'{general_text}\nThe url retrieved from conandata.yml is Invalid: ' + e.response.text)
    except requests.exceptions.Timeout as e:
        logging.error(f'{general_text}\nGot requests Timeout: ' + e.response.text)
    except requests.exceptions.RequestException as e:
        logging.error(f'{general_text}\nGeneral requests error: ' + e.response.text)


def get_source_folders_list(source_folders_missing, conan_dependencies: list):
    source_folder_libs = []
    for item in conan_dependencies:
        if item.get('reference') not in source_folders_missing:
            source_folder_libs.append(item.get('source_folder'))
            item['conandata_yml'] = os.path.join(item.get('export_folder'), 'conandata.yml')
    return source_folder_libs


def scan_with_unified_agent(config, dirs_to_scan):
    dirs = []
    for item in dirs_to_scan:
        dirs.append(str(Path(item).absolute()))

    unified_agent = ws_sdk.web.WSClient(user_key=config.user_key, token=config.org_token, url=config.ws_url, ua_path=config.unified_agent_path)
    unified_agent.ua_conf.projectPerFolder = str(False)
    unified_agent.ua_conf.productName = config.product_name
    unified_agent.ua_conf.productToken = config.product_token
    unified_agent.ua_conf.projectName = config.project_name
    unified_agent.ua_conf.projectToken = config.project_token
    unified_agent.ua_conf.includes = '**/*.*'
    unified_agent.ua_conf.excludes = str(f"**/ws_conan_scanned_*,{os.environ.get('WS_EXCLUDES', '')}")
    unified_agent.ua_conf.archiveExtractionDepth = str(UAArchiveFiles.ARCHIVE_EXTRACTION_DEPTH_MAX)
    unified_agent.ua_conf.archiveIncludes = list(UAArchiveFiles.ALL_ARCHIVE_FILES)
    unified_agent.ua_conf.logLevel = 'debug'
    # unified_agent.ua_conf.scanPackageManager = True #Todo - check for support in favor of https://docs.conan.io/en/latest/reference/conanfile/methods.html?highlight=system_requirements#system-requirements

    output = unified_agent.scan(scan_dir=dirs,
                                product_name=unified_agent.ua_conf.productName,
                                product_token=unified_agent.ua_conf.productToken,
                                project_name=unified_agent.ua_conf.projectName,
                                project_token=unified_agent.ua_conf.projectToken)
    logging.info(output[1])
    support_token = output[2]  # gets Support Token from scan output

    scan_status = True
    while scan_status:
        new_status = config.ws_conn.get_last_scan_process_status(support_token)
        logging.info(f"Scan data upload status :{new_status}")
        if new_status in ['UPDATED', 'FINISHED']:
            logging.info('scan upload completed')
            scan_status = False
        elif new_status in ['UNKNOWN', 'FAILED']:
            logging.warning('scan failed to upload...exiting program')
            sys.exit(1)
        else:
            time.sleep(20.0)


def update_conandta_yml_download_url_from_ws_index(config, conan_dependencies):
    def sync_ws_org_with_conan_source_library_from_the_index(conf, index_package):
        from ws_sdk.ws_errors import WsSdkClientGenericError
        try:
            response = conf.ws_conn.call_ws_api(request_type='getSourceLibraryInfo',
                                                kv_dict={"owner": index_package.get('indexOwner'),
                                                         "name": index_package.get('name'),
                                                         "version": index_package.get('indexVersion'),
                                                         "host": index_package.get('repoUrl'),
                                                         "downloadLink": index_package.get('indexDownloadUrl')})
        except ws_sdk.ws_errors.WsSdkServerGenericError as e:
            # logging.warning(e)
            pass
        return response.get('keyUuid')

    index_download_links = convert_dict_list_to_dict(lst=csv_to_json('https://unified-agent.s3.amazonaws.com/conan_index_url_map.csv'), key_desc='conanDownloadUrl')
    for package in conan_dependencies:
        package['counter'] = 0  # done in favor of next step.
        source = package.get('conandata_yml')
        url = extract_url_from_conan_data_yml(source, package)
        if index_download_links.get(url):
            index_package_data = index_download_links.get(url)
            new_url = index_package_data.get('indexDownloadUrl')
            package.update({'conandata_yml_download_url': new_url})

            # sync WS environemnt
            key_uuid = sync_ws_org_with_conan_source_library_from_the_index(config, index_package_data)
            package.update({'key_uuid': key_uuid})
        else:
            package.update({'conandata_yml_download_url': url})
    return conan_dependencies


def get_project_inventory_dict_by_download_link(due_diligence: dict, inventory):
    for library in inventory:
        if due_diligence.get(library.get('filename')):
            library['download_link'] = due_diligence[library['filename']].get('download_link')

    return convert_dict_list_to_dict(lst=inventory, key_desc='download_link')


def change_project_source_file_inventory_match(config, conan_dependencies_new):
    """changes source files mapping with changeOriginLibrary API"""

    def get_project_token_from_config(conf):
        if not conf.product_token:
            prod_token = conf.ws_conn.get_tokens_from_name(conf.product_name, token_type='product')[0]
        else:
            prod_token = conf.product_token

        if not config.project_token:
            projects_tokens = conf.ws_conn.get_scopes_from_name(conf.project_name, token_type='project')
            project_tokens_dict = convert_dict_list_to_dict(lst=projects_tokens, key_desc='product_token')
            proj_token = project_tokens_dict.get(prod_token).get('token')
        else:
            proj_token = conf.project_token
        return proj_token

    def process_project_due_diligence_report(conf, project_tok):
        project_due_diligence = conf.ws_conn.get_due_diligence(token=project_tok, report=False)
        for lib in project_due_diligence:
            if lib['library'][len(lib['library']) - 1] == '*':  # Remove astrix from the end of library name (occurs when licences number >1 )
                lib['library'] = lib['library'][:-1]

        return convert_dict_list_to_dict(project_due_diligence, key_desc='library')

    def prepare_project_source_files_to_remap(due_diligence_dict: dict, inventory):

        for source_file in inventory:
            source_file['sc_counter'] = 0  # Debug
            source_file['source_lib_full_name'] = source_file['library']['artifactId'] + '-' + source_file['library']['version']
            source_file['download_link'] = due_diligence_dict.get(source_file['source_lib_full_name']).get('download_link')

    def get_project_source_files_inventory_to_remap(conan_dependencies_new, project_source_files_inventory_to_remap_first_phase, project_inventory_dict_by_download_link, org_name):
        project_source_files_inventory_to_remap_second_phase = []
        libraries_key_uuid_and_source_files_sha1 = defaultdict(list)

        # ToDo project_source_files_inventory_to_remap_first_phase_dict_by_source_file_path = convert_dict_list_to_dict(project_source_files_inventory_to_remap_first_phase, 'path')

        missing_sf_counter_is_index_key_uuid = 0
        missing_sf_counter_is_not_index_key_uuid = 0
        for package in conan_dependencies_new:
            for source_file in project_source_files_inventory_to_remap_first_phase:
                if package['package_name'] in source_file['path'] or package['source_folder'] in source_file['path']:
                    if source_file.get('download_link') is not None and source_file.get('download_link') in str(project_inventory_dict_by_download_link.get(package['conandata_yml_download_url'])):
                        package['counter'] += 1
                    elif package.get('key_uuid'):
                        source_file['sc_counter'] += 1
                        libraries_key_uuid_and_source_files_sha1[json.dumps(package['key_uuid'])].append(source_file['sha1'])
                        missing_sf_counter_is_index_key_uuid += 1
                    else:
                        source_file['sc_counter'] += 1
                        project_source_files_inventory_to_remap_second_phase.append(source_file)
                        missing_sf_counter_is_not_index_key_uuid += 1
            if package['counter'] > 0:
                logging.info(f"for {package['package_name']} conan package: {package['counter']} source files are mapped to the correct library ({project_inventory_dict_by_download_link.get(package['conandata_yml_download_url'])['filename']}) in {org_name}")
            else:
                logging.info(f"for {package['package_name']} conan package: {package['counter']} source files are mapped to the correct library in {org_name}")
        missing_sf_counter = missing_sf_counter_is_index_key_uuid + missing_sf_counter_is_not_index_key_uuid
        logging.info(f"There are {missing_sf_counter} source files that can be re-mapped to the correct conan source library in {org_name}")
        return project_source_files_inventory_to_remap_second_phase, libraries_key_uuid_and_source_files_sha1

    def project_source_files_remap_first_phase(conf, libraries_key_uuid_and_source_files_sha1, project_token, org_name):
        from ws_sdk.ws_errors import WsSdkClientGenericError

        sha_ones_count = 0
        for key_uuid, sha1s in libraries_key_uuid_and_source_files_sha1.items():
            key_uuid = key_uuid.strip('"')
            try:
                conf.ws_conn.change_origin_of_source_lib(lib_uuid=key_uuid,
                                                         source_files_sha1=sha1s,
                                                         user_comments=f"Source files changed by Whitesource conan scan_{conf.date_time_now}")
            except ws_sdk.ws_errors.WsSdkServerGenericError as e:
                # logging.warning(e)
                pass
            project_inventory_updated = conf.ws_conn.get_inventory(token=project_token, with_dependencies=True, report=False)
            project_inventory_dict_by_key_uuid = convert_dict_list_to_dict(lst=project_inventory_updated, key_desc='keyUuid')
            logging.info(f"--{len(sha1s)} source files were moved to {project_inventory_dict_by_key_uuid.get(key_uuid).get('filename')} library in {org_name}")
            sha_ones_count += len(sha1s)

        logging.info(f"Total {sha_ones_count} source files were remapped to the correct libraries.")

    def get_project_source_files_inventory_to_remap_third_phase(project_source_files_inventory_to_remap_second_phase):
        project_source_files_inventory_to_remap_third_phase = []
        for source_file in project_source_files_inventory_to_remap_second_phase:
            if source_file['sc_counter'] < 2:  # this check is to reduce source files which were matched based on path+download link but contained another package name in its path.
                project_source_files_inventory_to_remap_third_phase.append(source_file)
            else:
                pass

        return project_source_files_inventory_to_remap_third_phase

    def get_packages_source_files_from_inventory_scan_results(project_source_files_inventory_to_remap_third_phase, conan_dependencies_new):
        packages_and_source_files_sha1 = defaultdict(list)
        for package in conan_dependencies_new:
            for source_file in project_source_files_inventory_to_remap_third_phase:
                if package['package_name'] in source_file['path'] or package['source_folder'] in source_file['path']:
                    source_file['download_link'] = package.get('conandata_yml_download_url')  # Todo check if can be removed
                    packages_and_source_files_sha1[json.dumps(package['package_name'])].append(source_file['sha1'])
        return packages_and_source_files_sha1

    from ws_sdk.ws_errors import WsSdkClientGenericError
    org_name = config.ws_conn_details.get('orgName')
    logging.info(f"Start validating source files matching accuracy in {org_name} compared to the local conan cache")

    # -=Filtering on project's source libraries download link compared with url from conandata.yml --> if it's the same , WhiteSource source files matching was correct and no need to change.=-

    # Reducing source files which were mapped to the correct source library ( based on url from conandata.yml )
    packages_dict_by_download_link = convert_dict_list_to_dict(lst=conan_dependencies_new, key_desc='conandata_yml_download_url')

    project_token = get_project_token_from_config(config)
    project_due_diligence_dict_by_library_name = process_project_due_diligence_report(config, project_token)
    project_source_files_inventory = config.ws_conn.get_source_file_inventory(report=False, token=project_token)

    prepare_project_source_files_to_remap(due_diligence_dict=project_due_diligence_dict_by_library_name, inventory=project_source_files_inventory)

    # get project inventory as it contain the keyUuid to be used later on
    project_inventory = config.ws_conn.get_inventory(token=project_token, with_dependencies=True, report=False)
    project_inventory_dict_by_download_link = get_project_inventory_dict_by_download_link(due_diligence=project_due_diligence_dict_by_library_name, inventory=project_inventory)

    for package in conan_dependencies_new:
        package.update({'package_name': package['reference'].replace('/', '-')})

    project_source_files_inventory_to_remap_second_phase, libraries_key_uuid_and_source_files_sha1 = get_project_source_files_inventory_to_remap(conan_dependencies_new, project_source_files_inventory, project_inventory_dict_by_download_link, org_name)
    if len(libraries_key_uuid_and_source_files_sha1) > 0:
        project_source_files_remap_first_phase(config, libraries_key_uuid_and_source_files_sha1, project_token, org_name)

    if len(project_source_files_inventory_to_remap_second_phase) > 0:
        project_source_files_inventory_to_remap_third_phase = get_project_source_files_inventory_to_remap_third_phase(project_source_files_inventory_to_remap_second_phase)

        remaining_conan_local_packages_and_source_files_sha1 = get_packages_source_files_from_inventory_scan_results(project_source_files_inventory_to_remap_third_phase, conan_dependencies_new)  # Todo check bzip2

        ####
        # Changing mis-mapped source files to optional library based on conan download url with global search
        counter = 0
        packages_dict_by_package_name = convert_dict_list_to_dict(lst=conan_dependencies_new, key_desc='package_name')

        for package, sha1s in remaining_conan_local_packages_and_source_files_sha1.items():  # Todo - add threads
            package = json.loads(package)
            if packages_dict_by_package_name[package].get('key_uuid'):
                logging.info(f"found a match for miss configured source files of {package}")
                try:
                    config.ws_conn.change_origin_of_source_lib(lib_uuid=packages_dict_by_package_name[package]['key_uuid'], source_files_sha1=sha1s, user_comments='Source files changed by Whitesource conan scan_' + config['date_time_now'])
                except ws_sdk.ws_errors.WsSdkServerGenericError as e:
                    # logging.warning(e)
                    pass
                no_match = False
                counter += 1
                logging.info(f"--{counter}/{len(remaining_conan_local_packages_and_source_files_sha1)} libraries were matched ( {len(sha1s)} mis-configured source files from {package} conan package were matched to WS source library )")
            ####
            else:
                logging.info(f"Trying match the remaining miss configured source files of {package} with global search")
                # package = json.loads(package)
                library_name = package.partition('-')[0]
                library_search_result = config.ws_conn.get_libraries(library_name)

                # Filtering results - only for 'Source Library'
                source_libraries = []
                for library in library_search_result:
                    if library['type'] == 'Source Library':
                        source_libraries.append(library)

                source_libraries_dict_from_search_by_download_link = convert_dict_list_to_dict(source_libraries, key_desc=str('url'))
                check_url = packages_dict_by_package_name[package]['conandata_yml_download_url']

                if source_libraries_dict_from_search_by_download_link.get(check_url):
                    library_key_uuid = source_libraries_dict_from_search_by_download_link[check_url].get('keyUuid')
                    logging.info(f"found a match for miss configured source files of {package}")
                    try:
                        config.ws_conn.change_origin_of_source_lib(lib_uuid=library_key_uuid, source_files_sha1=sha1s, user_comments='Source files changed by Whitesource conan scan_' + config['date_time_now'])
                    except ws_sdk.ws_errors.WsSdkServerGenericError as e:
                        # logging.warning(e)
                        pass
                    no_match = False
                    counter += 1
                    logging.info(f"--{counter}/{len(remaining_conan_local_packages_and_source_files_sha1)} libraries were matched ( {len(sha1s)} mis-configured source files from {package} conan package were matched to {source_libraries_dict_from_search_by_download_link[check_url]['filename']} WS source library )")

                else:
                    no_match = True

            if no_match:
                logging.info(f" Did not find match for {package} package remaining source files.")


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
                url = url[-1]
            return url
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        logging.warning(f"Could not find {package} conandata.yml file")


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


def create_configuration():
    """reads the configuration from cli."""

    def get_args(arguments) -> dict:
        """Get configuration arguments"""

        logging.info('Start analyzing arguments.')

        parser = argparse.ArgumentParser(description='argument parser')

        parser.add_argument('-s', "--" + KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN, help="keep the install folder after run", dest='keep_conan_install_folder_after_run', required=False, default=KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN_DEFAULT, type=str2bool)
        parser.add_argument('-b', "--" + INCLUDE_BUILD_REQUIRES_PACKAGES, help="If ture , list conan packages with conan info /path/to/conanfile --paths --dry-build.", type=str2bool, required=False, default=INCLUDE_BUILD_REQUIRES_PACKAGES_DEFAULT, dest='include_build_requires_packages')
        parser.add_argument('-p', "--" + CONAN_RUN_PRE_STEP, help="run conan install --build", dest='conan_run_pre_step', required=False, default=CONAN_RUN_PRE_STEP_DEFAULT, type=str2bool)
        parser.add_argument('-g', "--" + CHANGE_ORIGIN_LIBRARY, help="True will attempt to match libraries per package name and version", dest='change_origin_library', required=False, default=CHANGE_ORIGIN_LIBRARY_DEFAULT, type=str2bool)
        parser.add_argument('-u', '--' + WS_URL, help='The WhiteSource organization url', required=True, dest='ws_url')
        parser.add_argument('-k', '--' + USER_KEY, help='The admin user key', required=True, dest='user_key')
        parser.add_argument('-t', '--' + ORG_TOKEN, help='The organization token', required=True, dest='org_token')
        parser.add_argument('--' + PRODUCT_TOKEN, help='The product token', required=False, dest='product_token')
        parser.add_argument('--' + PROJECT_TOKEN, help='The project token', required=False, dest='project_token')
        parser.add_argument('--' + PRODUCT_NAME, help='The product name', required=False, dest='product_name')
        parser.add_argument('--' + PROJECT_NAME, help='The project name', required=False, dest='project_name')
        # parser.add_argument('-m', '--' + PROJECT_PARALLELISM_LEVEL, help='The number of threads to run with', required=not is_config_file, dest='project_parallelism_level', type=int, default=PROJECT_PARALLELISM_LEVEL_DEFAULT, choices=PROJECT_PARALLELISM_LEVEL_RANGE)
        parser.add_argument('-d', "--" + PROJECT_PATH, help=f"The directory which contains the conanfile.txt / conanfile.py path", type=Path, required=True, dest='project_path')
        remaining = parser.parse_known_args()
        parser.add_argument('-a', "--" + UNIFIED_AGENT_PATH, help=f"The directory which contains the Unified Agent", type=Path, required=False, default=remaining[0].project_path, dest='unified_agent_path')
        remaining = parser.parse_known_args()
        parser.add_argument('-i', "--" + CONAN_INSTALL_FOLDER, help=f"The folder in which the installation of packages outputs the generator files with the information of dependencies. Format: Y-m-d-H-M-S-f", type=Path, required=False, default=remaining[0].project_path, dest='conan_install_folder')

        args_dict = vars(parser.parse_args())

        logging.info('Finished analyzing arguments.')
        return args_dict

    args = sys.argv[1:]
    if len(args) > 0:
        params_conf = get_args(args)
        return Config(conf=params_conf)


def main():
    config = create_configuration()

    start_time = datetime.now()
    logging.info(f"Start running {__description__} on token {config.org_token}.")
    validate_conan_installed()
    map_conan_profile_values()
    validate_project_manifest_file_exists(config)

    if config.conan_run_pre_step:
        run_conan_install_command(config)

    conan_dependencies = map_all_dependencies(config)

    dirs_to_scan = [config.project_path]

    source_folders_missing = conan_cache_packages_source_folder_missing(conan_dependencies)

    if source_folders_missing:
        get_dependencies_from_download_source(config, source_folders_missing, conan_dependencies)

    source_from_conan_cache = get_source_folders_list(source_folders_missing, conan_dependencies)
    for item in source_from_conan_cache:
        dirs_to_scan.append(item)

    # Adding {'conandata_yml_download_url':url} dictionary for each conan package and aligning with ws index convention
    conan_dependencies_new = update_conandta_yml_download_url_from_ws_index(config, conan_dependencies)

    scan_with_unified_agent(config, dirs_to_scan)

    if config.change_origin_library:
        change_project_source_file_inventory_match(config, conan_dependencies_new)

    logging.info(f"Finished running {__description__}. Run time: {datetime.now() - start_time}")

    if not config.keep_conan_install_folder_after_run:
        try:
            shutil.rmtree(config.temp_dir)
            logging.info(f"removed conanInstallFolder : {config.temp_dir}")
        except OSError as e:
            logging.error("Error: %s - %s." % (e.filename, e.strerror))
    else:
        temp_path = Path(config.project_path, 'ws_conan_scanned_' + config.date_time_now)
        logging.info(f"renaming {config.temp_dir} to {temp_path}")
        shutil.move(config.temp_dir, temp_path)


if __name__ == '__main__':
    gc.collect()
    main()
