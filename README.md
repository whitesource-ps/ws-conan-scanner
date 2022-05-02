[![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)](https://www.whitesourcesoftware.com/)  
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)

[![CI](https://github.com/whitesource-ps/ws-conan-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-conan-scanner/actions/workflows/ci.yml)
[![Python 3.7](https://upload.wikimedia.org/wikipedia/commons/thumb/7/76/Blue_Python_3.7%2B_Shield_Badge.svg/86px-Blue_Python_3.7%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-370/)

[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/ws-conan-scanner)](https://github.com/whitesource-ps/ws-conan-scanner/releases/latest)

# [WhiteSource Conan Scanner](https://github.com/whitesource-ps/ws-conan-scanner)

### What does the script do?

The script scans [Conan.io](https://docs.conan.io/en/latest/) projects and resolves dependencies with WhiteSource's Unified Agent.

### Supported Operating Systems

- **Linux (Bash):**    CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**    10, 2012, 2016
- **Docker container

### Prerequisites

- Python 3.7 or above.
- Conan package manager installed and `sysrequires_mode = enabled`
- Java JDK 8 ,Java JDK 11.

### Installation

Execute `pip install ws-conan-scanner`

### Configuration Parameters

| Parameter                                                          |  Type   |                   Required                    |           Default            | Description                                                                                                                                                                                               |
|--------------------------------------------------------------------|:-------:|:---------------------------------------------:|:----------------------------:|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **&#x2011;h,&nbsp;&#x2011;&#x2011;help**                           | switch  |                      No                       |                              | Shows help and usage menu.                                                                                                                                                                                |
| **&#x2011;d,&nbsp;&#x2011;&#x2011;projectPath**                    | string  |                      Yes                      |                              | The full path directory which contains the `conanfile.txt` / `conanfile.py` path.                                                                                                                         |
| **&#x2011;a,&nbsp;&#x2011;&#x2011;unifiedAgentPath**               | string  |                      No                       |         projectPath          | The full path directory which contains the Unified Agent ( will be downloaded if not found on in path.                                                                                                    |
| **&#x2011;i,&nbsp;&#x2011;&#x2011;conanInstallFolder**             | string  |                      No                       | projectPath/`%Y%m%d%H%M%S%f` | The folder where the installation of packages outputs the generator files with the information of dependencies. Format: `%Y%m%d%H%M%S%f` .                                                                |
| **&#x2011;i,&nbsp;&#x2011;&#x2011;conanProfileName**               | string  |                      No                       |          `default`           | The name of the conan profile .                                                                                                                                                                           |
| **&#x2011;s,&nbsp;&#x2011;&#x2011;keepConanInstallFolderAfterRun** | boolean |                      No                       |            False             | keeps the Conan install folder after run.                                                                                                                                                                 |
| **&#x2011;b,&nbsp;&#x2011;&#x2011;includeBuildRequiresPackages**   | boolean |                      No                       |             True             | If True, the scanner will include [build_requirements packages](https://docs.conan.io/en/latest/devtools/build_requires.html).                                                                            |
| **&#x2011;p,&nbsp;&#x2011;&#x2011;conanRunPreStep**                | boolean |                      No                       |            False             | Runs `conan install --build`.                                                                                                                                                                             |
| **&#x2011;g,&nbsp;&#x2011;&#x2011;changeOriginLibrary**            | boolean |                      No                       |             True             | Auto run of [Origin Library change](https://whitesource.atlassian.net/wiki/spaces/WD/pages/34013522/Changing+the+Origin+Library+for+Source+Files) for conan source libraries in Whitesource organization. |
| **&#x2011;u,&nbsp;&#x2011;&#x2011;logFilePath**                    | string  |                      No                       |                              | The full path Path to the conan_scanner_log_`%Y%m%d%H%M%S%f`.log file.                                                                                                                                    |
| **&#x2011;u,&nbsp;&#x2011;&#x2011;wsUrl**                          | string  |                      Yes                      |                              | The WhiteSource organization url.                                                                                                                                                                         |
| **&#x2011;k,&nbsp;&#x2011;&#x2011;userKey**                        | string  |                      Yes                      |                              | The user ( Product Admin ) key.                                                                                                                                                                           |
| **&#x2011;t,&nbsp;&#x2011;&#x2011;orgToken**                       | string  |                      Yes                      |                              | The organization token.                                                                                                                                                                                   |
| **&nbsp;&#x2011;&#x2011;productName**                              | string  | Only required if projectToken is not defined. |                              | The product name.                                                                                                                                                                                         |
| **&nbsp;&#x2011;&#x2011;projectName**                              | string  | Only required if projectToken is not defined. |                              | The project name.                                                                                                                                                                                         |
| **&nbsp;&#x2011;&#x2011;productToken**                             | string  | Only required if projectToken is not defined. |                              | The product token.                                                                                                                                                                                        |
| **&nbsp;&#x2011;&#x2011;projectToken**                             | string  | Only required if projectName is not defined.  |                              | The project token.                                                                                                                                                                                        |

### Execution

From the command line:

With default behavior

```
ws_conan_scanner  --projectPath /path/to/folder/with/conanfile  --wsUrl https://saas.whitesourcesoftware.com --userKey 12345678 --orgToken 87654321 --productName TestProd --projectName TestProj
```

With customized behavior

```
ws_conan_scanner  --projectPath /path/to/folder/with/conanfile --unifiedAgentPath /path/to/folder/with/ws/unified/agent --conanInstallFolder /path/to/install/folder --keepConanInstallFolderAfterRun True  --includeBuildRequiresPackages True --conanRunPreStep True --changeOriginLibrary True --wsUrl https://saas.whitesourcesoftware.com --userKey 12345678 --orgToken 87654321 --productName TestProd --projectName TestProj --logFilePath /path/to/folder/of/log/file
```

### Unified Agent Specifications

The Conan scanner is a wrapper to the Whitesource [Unified Agent](https://whitesource.atlassian.net/wiki/spaces/WD/pages/804814917/Unified+Agent+Overview).

To set any of the [Unified Agent Configuration Parameters](https://whitesource.atlassian.net/wiki/spaces/WD/pages/1544880156/Unified+Agent+Configuration+Parameters) , please use the `WS_` [Environemnt Variables](https://whitesource.atlassian.net/wiki/spaces/WD/pages/1544880156/Unified+Agent+Configuration+Parameters#Configuring-the-Unified-Agent-by-Environment-Variables) convention.

For the `excludes` parameter the following extensions are hardcoded :

```
excludes = **/ws_conan_scanned_*,jna-1649909383
```

You can add more [extensions](https://whitesource.atlassian.net/wiki/spaces/WD/pages/1544880156/Unified+Agent+Configuration+Parameters#Includes%2FExcludes-Glob-Patterns) with `WS_EXCLUDES` environment variable .

### Author

WhiteSource Software ©