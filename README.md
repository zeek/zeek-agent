# Build instructions

## Initialize the osquery build environment
1. Clone the osquery repository: `git clone https://github.com/osquery/osquery osquery-extension-sdk-env`
2. Switch to osquery version 3.3.2 to use the original SDK: `( cd osquery-extension-sdk-env && git fetch --tags && git checkout -b v3.3.2 3.3.2 )`
3. Install the required system dependencies and third party libraries: `( cd osquery-extension-sdk-env && make sysprep )`

## Build the extension
1. Clone the osquery-zeek repository: `git clone https://github.com/<organization_name>/osquery-zeek`
2. Link the extension source code inside the osquery repository: `ln -s "$(realpath osquery-zeek)" osquery-extension-sdk-env/external/extension_osquery-zeek`
3. **Optional**: Disable the osquery tests and benchmarks: `export SKIP_TESTS=1 ; export SKIP_BENCHMARKS=1`
4. Build the extension: `( cd osquery-extension-sdk-env && make -j $(nproc) )`

Once built, the extension executable can be found at the following path: `osquery-extension-sdk-env/build/linux/external/extension_osquery-zeek/zeek-extension/osquery-zeek.ext`

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

## /etc/osquery/osquery.conf
```
{
  "options": {
    # Enable extensions; make sure the Zeek components we need are marked as required
    "disable_extensions": 0,
    "extensions_timeout": 10,
    "extensions_require": "zeek_logger,zeek_distributed",

    # Enable the Zeek distributed plugin
    "disable_distributed": 0,
    "distributed_plugin": "zeek_distributed",

    # Enable the Zeek logger plugin
    "logger_path": "/var/log/osquery",
    "logger_plugin": "filesystem,zeek_logger",
    "logger_event_type": 0,

    # Enable events
    "disable_events": 0,

    # Audit settings
    "disable_audit": 0,
    "audit_allow_config": 1,
    "audit_allow_sockets": 1,
    "audit_force_reconfigure": 1,
    "audit_persist": 1,
    "audit_allow_sockets": 1,
    "audit_allow_fork_process_events": 1
  }
}
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
