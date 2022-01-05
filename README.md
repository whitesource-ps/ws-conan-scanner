[![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)](https://www.whitesourcesoftware.com/)  
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)

[![CI](https://github.com/whitesource-ps/ws-conan-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-conan-scanner/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)

[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-conan-scanner)](https://github.com/whitesource-ps/ws-conan-scanner/releases/latest)  

# [WhiteSource Conan Scanner](https://github.com/whitesource-ps/ws-conan-scanner)

### What does the script do?
The script performs a scan of conan packages source file with WhiteSource's Unified Agent.

### Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016
- **Docker container

### Prerequisites
- Python 3.6 or above.
- conan is installed
- sysrequires_mode = enabled

### Installation
1. Download and unzip **ws-conan-scanner.zip**.
2. From the command line, navigate to the ws_conan_scanner directory and install the package:  
   `pip install -r requirements.txt`.
3. Edit the `/ws_conan_scanner/params.config` file and update the relevant parameters (see the configuration parameters below) or
   use a cmd line for running the `/ws_conan_scanner/conan_scanner.py` script.

### Configuration Parameters'
```
==================================================================================================================================================================================
| config file             | cli                             | Environment Variables        | Default  | Description                                                              |
==================================================================================================================================================================================
| wsUrl                   | -u,  --wsUrl                    | WS_WS_URL                    |          | WhiteSource application page >Home >Admin >Integration >Server URL       |
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| userKey                 | -k,  --userKey                  | WS_USER_KEY                  |          | WhiteSource application page >Profile >User Keys                         |
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| orgToken                | -t,  --orgToken                 | WS_ORG_TOKEN                 |          | WhiteSource application page >Home >Integrate tab >Organization >API Key |
==================================================================================================================================================================================
```
### Execution
From the command line:
`python conan_scanner.py -u $wsUrl -k $userKey -t $orgToken -m $projectParallelismLevel`

Using a config file:
`python conan_scanner.py -c / --configFile <CONFIG_FILE>`

Environment Variables:
- A parameter name, as it is defined in the configuration file, is converted to upper case with underscore (`_`) separators, and **WS**_ prefix is added.
- For example, the `wsUrl` parameter can be set using the `WS_WS_URL ` environment variable.
- If an environment variable exists, it will overwrite any value that is defined for the matching parameter in the command line/configuration file.

### Author
WhiteSource Software ©