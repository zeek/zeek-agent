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

# Running cppcheck

When the `cppcheck` tool is available, the `zeek_cppcheck` target can be built to run cppcheck against the extension source files.

Note: It's better not to use the one provided by the osquery toolchain (/usr/local/osquery/bin/cppcheck) as it's outdated and does not support the `compile_commands.json` format.

# Installing Zeek

To install Zeek and its osquery script framework, follow [these
instructions](https://github.com/zeek/osquery-framework).

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
``` json
{
  "host": "localhost",
  "port": "9999",

  "group_list": {
    "group1": "geo/de/hamburg",
    "group2": "orga/uhh/cs/iss"
  },

  "authentication": {
    "certificate_authority": "/path/to/certs.pem",
    "client_certificate": "/path/to/client.crt",
    "client_key": "/path/to/client.key"
  }
}
```

The `authentication` object is optional, but strongly recommended for production environments.

# Launching osquery
Depending on how osquery was installed, you may have to launch it manually or with systemd. The above options, save for the zeek.conf configuration file, can also be passed directly to osquery as command line flags. The extensions.load file can be replaced with the `--extension=/path/to/ext` parameter.
