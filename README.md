[![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)](https://www.whitesourcesoftware.com/)  
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)

[![CI](https://github.com/whitesource-ps/ws-conan-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-conan-scanner/actions/workflows/ci.yml)
[![Python 3.7](https://upload.wikimedia.org/wikipedia/commons/thumb/7/76/Blue_Python_3.7%2B_Shield_Badge.svg/86px-Blue_Python_3.7%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-370/)

[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-conan-scanner)](https://github.com/whitesource-ps/ws-conan-scanner/releases/latest)  

# [WhiteSource Conan Scanner](https://github.com/whitesource-ps/ws-conan-scanner)

### What does the script do?
The script scans [Conan.io](https://docs.conan.io/en/latest/) projects and resolves dependcies with WhiteSource's Unified Agent.

### Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016
- **Docker container

### Prerequisites
- Python 3.7 or above.
- Conan is installed
- Java JDK 8 ,Java JDK 11.

### Installation
1. Download and unzip **ws-conan-scanner.zip**.
2. From the command line, navigate to the `ws_conan_scanner` directory and install the package:  
   `pip install -r requirements.txt`.
3. Edit the `/ws_conan_scanner/params.config` file and update the relevant parameters (see the configuration parameters below) or
   use a command line for running the `/ws_conan_scanner/conan_scanner.py` script.

### Configuration Parameters'
```shell
usage: conan_scanner.py [-h] [-c CONF_F] -d PROJECT_PATH -a UNIFIED_AGENT_PATH -if CONAN_INSTALL_FOLDER -s KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN -u WS_URL -k USER_KEY -t ORG_TOKEN --productToken PRODUCT_TOKEN --projectToken PROJECT_TOKEN --productName PRODUCT_NAME --projectName PROJECT_NAME

argument parser

optional arguments:
  -h, --help            show this help message and exit
  -c CONF_F, --configFile CONF_F
                        The config file
  -d PROJECT_PATH, --projectPath PROJECT_PATH
                        The directory which contains the conanfile.txt / conanfile.py path
  -a UNIFIED_AGENT_PATH, --unifiedAgentPath UNIFIED_AGENT_PATH
                        The directory which contains the Unified Agent
  -if CONAN_INSTALL_FOLDER, --conanInstallFolder CONAN_INSTALL_FOLDER
                        The folder in which the installation of packages outputs the generator files with the information of dependencies.
  -s KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN, --keepConanInstallFolderAfterRun KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN
                        keep the install folder after run
  -u WS_URL, --wsUrl WS_URL
                        The organization url
  -k USER_KEY, --userKey USER_KEY
                        The admin user key
  -t ORG_TOKEN, --orgToken ORG_TOKEN
                        The organization token
  --productToken PRODUCT_TOKEN
                        The product token
  --projectToken PROJECT_TOKEN
                        The project token
  --productName PRODUCT_NAME
                        The product name
  --projectName PROJECT_NAME
                        The project name

```
### Execution
From the command line:
```shell
python conan_scanner.py -d PROJECT_PATH -a UNIFIED_AGENT_PATH -if CONAN_INSTALL_FOLDER -s KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN -u WS_URL -k USER_KEY -t ORG_TOKEN --productName PRODUCT_NAME --projectName PROJECT_NAME
```

Using a config file:
```shell
python conan_scanner.py -c / --configFile <CONFIG_FILE>`
```

Environment Variables:
- A parameter name, as it is defined in the configuration file, is converted to upper case with underscore (`_`) separators, and **WS**_ prefix is added.
- For example, the `wsUrl` parameter can be set using the `WS_WS_URL ` environment variable.
- If an environment variable exists, it will overwrite any value that is defined for the matching parameter in the command line/configuration file.

### Author
WhiteSource Software ©