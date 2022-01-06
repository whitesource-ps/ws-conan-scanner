[![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)](https://www.whitesourcesoftware.com/)  
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)

[![CI](https://github.com/whitesource-ps/ws-conan-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-conan-scanner/actions/workflows/ci.yml)
[![Python 3.7](https://upload.wikimedia.org/wikipedia/commons/thumb/7/76/Blue_Python_3.7%2B_Shield_Badge.svg/86px-Blue_Python_3.7%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-370/)

[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-conan-scanner)](https://github.com/whitesource-ps/ws-conan-scanner/releases/latest)

# [WhiteSource Conan Scanner](https://github.com/whitesource-ps/ws-conan-scanner)

### What does the script do?
The script scans [Conan.io](https://docs.conan.io/en/latest/) projects and resolves dependencies with WhiteSource's Unified Agent.

### Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016
- **Docker container

### Prerequisites
- Python 3.7 or above.
- Conan package manager installed.
- Java JDK 8 ,Java JDK 11.

### Installation
1. Download and unzip **ws-conan-scanner.zip**.
2. From the command line, navigate to the `ws_conan_scanner` directory and install the package:  
   `pip install -r requirements.txt`.
3. Edit the `/ws_conan_scanner/params.config` file and update the relevant parameters (see the configuration parameters below) or
   use a command line for running the `/ws_conan_scanner/conan_scanner.py` script.

### Configuration Parameters

| Parameter | Type | Required | Description |
| :--- | :---: | :---: | :--- |
| **&#x2011;h,&nbsp;&#x2011;&#x2011;help** | switch | No | Show help and usage menu. |
| **&#x2011;c,&nbsp;&#x2011;&#x2011;configFile** | string | No | The config file path.|
| **&#x2011;d,&nbsp;&#x2011;&#x2011;projectPath** | string | Yes | The directory which contains the conanfile.txt / conanfile.py path. |
| **&#x2011;a,&nbsp;&#x2011;&#x2011;unifiedAgentPath** | string | No | The directory which contains the Unified Agent. |
| **&#x2011;if,&nbsp;&#x2011;&#x2011;conanInstallFolder** | string | No | The folder where the installation of packages outputs the generator files with the information of dependencies. Format: %Y%m%d%H%M%S%f |
| **&#x2011;s,&nbsp;&#x2011;&#x2011;keepConanInstallFolderAfterRun** | boolean | No | keeps the Conan install folder after run. |
| **&#x2011;u,&nbsp;&#x2011;&#x2011;wsUrl** | string | Yes | The WhiteSource organization url.|
| **&#x2011;k,&nbsp;&#x2011;&#x2011;userKey** | string | Yes | The user key.|
| **&#x2011;t,&nbsp;&#x2011;&#x2011;orgToken** | string | Yes | The organization token.|
| **&#x2011;c,&nbsp;&#x2011;&#x2011;productName** | string | No | The product name.|
| **&#x2011;c,&nbsp;&#x2011;&#x2011;projectName** | string | No | The project name.|
| **&#x2011;c,&nbsp;&#x2011;&#x2011;productToken** | string | No | The product token. If not defined, then productName must be defined instead.|
| **&#x2011;c,&nbsp;&#x2011;&#x2011;projectToken** | string | No | The project token .If not defined, then projectName must be defined instead.|




### Execution
From the command line:
```shell
python conan_scanner.py -d PROJECT_PATH -a UNIFIED_AGENT_PATH -if CONAN_INSTALL_FOLDER -s KEEP_CONAN_INSTALL_FOLDER_AFTER_RUN -u WS_URL -k USER_KEY -t ORG_TOKEN --productName PRODUCT_NAME --projectName PROJECT_NAME

For Example:
------------
python .\conan_scanner.py  -d /path/to/folder/with/conanfile --wsUrl https://saas.whitesourcesoftware.com --userKey 12345678 --orgToken 87654321 --productName TestProd --projectName TestProj
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