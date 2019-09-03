# About

This extension allows Zeek to perform live queries against osquery tables.

The original code has been implemented by [iBigQ](https://github.com/iBigQ) and can be found in [his osquery fork](https://github.com/iBigQ/osquery).

# Build instructions

## Initialize the osquery build environment
1. Clone the osquery repository: `git clone https://github.com/osquery/osquery osquery-extension-sdk-env`
2. Switch to osquery version 3.3.2 to use the original SDK: `( cd osquery-extension-sdk-env && git fetch --tags && git checkout -b v3.3.2 3.3.2 )`
3. Install the required system dependencies and third party libraries: `( cd osquery-extension-sdk-env && make sysprep )`

## Build the extension
1. Clone the osquery-extension repository: `git clone https://github.com/zeek/osquery-extension.git --recursive`
2. Link the extension source code inside the osquery repository: `ln -s "$(realpath osquery-extension)" osquery-extension-sdk-env/external/extension_osquery-zeek`
3. **Optional**: Disable the osquery tests and benchmarks: `export SKIP_TESTS=1 ; export SKIP_BENCHMARKS=1`
4. Build the extension: `( cd osquery-extension-sdk-env && make -j $(nproc) )`

Once built, the extension executable can be found at the following path: `osquery-extension-sdk-env/build/linux/external/extension_osquery-zeek/zeek-extension/osquery-zeek.ext`

# Running the tests

The `zeek_tests` target can be used to build the tests if the `ZEEK_BUILD_TESTING` CMake option has been enabled. When using the old osquery 3.x SDK, this setting has to be exported as an environment variable.

It is possible to automatically compile and run them by building the `run_zeek_tests` target.

# Running clang-tidy

The `zeek_tidy` target can be built to run clang-tidy on the extension code. If you are on Ubuntu 18, you should install the `clang` package (to solve a symlink issue in the system include folder) and the `clang-tidy-8` from the package manager.

# Installing Zeek
## Main program files
The Zeek install instructions can be found [on the official website](https://zeek.org/download/packages.html).

Make sure that the `bin` folder for Zeek is inside the PATH environment variable. This can be usually achieved with the following command: `export PATH=${PATH}:/opt/bro/bin`.

## Installing the osquery scripts
1. Install the Zeek package manager: `pip install zkg`
2. Initialize the package manager configuration: `zkg autoconfig`
3. Enable the zeek-osquery-packages repository: `echo "osquery = https://github.com/iBigQ/zeek-osquery-packages" >> "${HOME}/.zkg/config" && zkg refresh`
4. Install the scripts: `zkg install zeek-osquery-framework && zkg install --nodeps zeek-osquery-queries`
5. Enable the scripts within Zeek: `zkg load zeek-osquery-framework && zkg load zeek-osquery-queries`

# Installing osquery
The latest version is required in order to run the extension correctly. Releases can be downloaded from the [GitHub release page](https://github.com/osquery/osquery/releases).

# Configuration
## /etc/osquery/extensions.load
This file should contain the full path to the `osquery-zeek.ext` binary.

## /etc/osquery.flags.default
```
--logger_path=/var/log/osquery
--disable_audit=false
--audit_allow_config=true
--audit_allow_sockets=true
--audit_force_reconfigure=true
--audit_persist=true
--audit_allow_fork_process_events=true
--disable_extensions=false
--extensions_timeout=10
--extensions_required=zeek_logger,zeek_distributed
--disable_distributed=false
--distributed_plugin=zeek_distributed
--logger_plugin=zeek_logger
--logger_event_type=false
--disable_events=false
```

## /etc/osquery/zeek.conf
```
{
  "host": "localhost",
  "port": "9999",

  "group_list": {
    "group1": "geo/de/hamburg",
    "group2": "orga/uhh/cs/iss"
  }
}
```

# Launching osquery
Depending on how osquery was installed, you may have to launch it manually or with systemd. The above options, save for the zeek.conf configuration file, can also be passed directly to osquery as command line flags. The extensions.load file can be replaced with the `--extension=/path/to/ext` parameter.
