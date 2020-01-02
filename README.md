# zeek-agent

The Zeek Agent is an endpoint monitoring tool that reports socket and process events to a [Zeek](https://zeek.org) server instance. Event data is captured from Audit using the Unix domain socket plugin that comes with Audisp, and is then presented as a SQL database using SQLite virtual tables. It is optionally possible to enable osquery support, allowing Zeek to access all its non-evented tables.

Pre-built packages are available in the [releases page](https://github.com/zeek/osquery-extension/releases).

## Building from source

### Introduction

For users that are already familiar with CMake, the project should be easy to build once the required dependencies have been installed and the repository has been cloned with all the submodules. No special steps are required for the configure and build steps.

Project options have been grouped under the `ZEEK` prefix and will show up in configuration tools such as `ccmake` and `cmake-gui`.

It is also possible to run the following script to configure, build, test and generate the packages: `scripts/build_release.sh`

### Obtaining the source code

Clone the repository along with all the necessary submodules: `git clone https://github.com/zeek/osquery-extension --recursive`

If the repository has already been cloned without `--recursive` (or if the repository is being updated with new commits), then the submodules can be updated again with the following commands:

```
git submodule sync --recursive
git submodule update --init --recursive
```

### Building with the system compiler, without osquery (standalone)

This is a lightweight, standalone build of Zeek Agent. Make sure that both the system compiler and C++ library support C++17 (Ubuntu 19.10 is recommended). The generated binaries and packages are not redistributable as they will depend on system libraries.

Make sure the following packages are installed:

* libssl-dev
* clang

Configure and build zeek-agent:

```
mkdir build && cd build

cmake -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DCMAKE_C_COMPILER:STRING=clang -DCMAKE_CXX_COMPILER:STRING=clang++ -DZEEK_AGENT_ENABLE_INSTALL:BOOL=ON -DZEEK_AGENT_ENABLE_TESTS:BOOL=ON /path/to/source

cmake --build . -j $(($(nproc)+1))
```

Run the tests:

```
cmake --build . --target zeek_agent_tests
```

### Building with the osquery-toolchain, without osquery (standalone)

This is a lightweight, standalone build of Zeek Agent. For this build type, there are no dependencies other than the osquery toolchain. Generated binaries and packages are redistributable, and will work on any distribution that ships glibc >= 2.12 (CentOS 6/Ubuntu 16.04 and above). Since the toolchain is self-contained, this build procedure should work fine on any recent distribution - but only Ubuntu 18.10 is officially supported.

Acquire the toolchain from the [osquery-toolchain release page](https://github.com/osquery/osquery-toolchain/releases) and extract it to `/opt/osquery-toolchain`.

Configure and build zeek-agent:

```
mkdir build && cd build

cmake -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DZEEK_AGENT_TOOLCHAIN_PATH:PATH=/opt/osquery-toolchain -DZEEK_AGENT_ENABLE_INSTALL:BOOL=ON -DZEEK_AGENT_ENABLE_TESTS:BOOL=ON /path/to/source

cmake --build . -j $(($(nproc)+1))
```

Run the tests:

```
cmake --build . --target zeek_agent_tests
```

### Building with the osquery-toolchain, with osquery

This is the full build of Zeek Agent, and the recommended way of generating binaries and packages. There are no dependencies other than osquery and its toolchain. Generated binaries and packages are redistributable, and will work on any distribution that ships glibc >= 2.12 (CentOS 6/Ubuntu 16.04 and above). Since the toolchain is self-contained, this build procedure should work fine on any recent distribution - but only Ubuntu 18.10 is officially supported.

The first step is to configure and build osquery, using the [official osquery build guide](https://osquery.readthedocs.io/en/latest/development/building).

Link the Zeek Agent folder inside the osquery source tree

```
ln -s /path/to/zeek-agent/source/folder /path/to/osquery/source/folder/external/extension_zeek-agent
```

Update the CMake configuration, from within the osquery build folder

```
cmake -DZEEK_AGENT_ENABLE_INSTALL:BOOL=ON -DZEEK_AGENT_ENABLE_TESTS:BOOL=true /path/to/osquery/source/folder
```

Build Zeek Agent

```
cmake --build . -j $(($(nproc)+1))
```

Run the tests:

```
cmake --build . --target zeek_agent_tests
```

### Creating packages

Once Zeek Agent has already been configured and built, the packaging project can be used to generate packages. The `rpm` and `dpkg` binaries are required to generate RPM and DEB packages, and if they are not present those formats will be automatically disabled. The TGZ output is always enabled and will generate a .tar.gz package file.

Install Zeek Agent

```
cd build_folder

mkdir install
export DESTDIR="$(realpath install)"

cmake --build . --target install
```

Configure the packaging project

```
mkdir package_build && cd package_build

cmake -DZEEK_AGENT_INSTALL_PATH:PATH="${DESTDIR}" /path/to/zeek-agent/source/packaging
```

Create the packages

```
cmake --build . --target package
```

## Configuration

**Audit configuration**

* The auditd daemon must be enabled and running: `systemctl enable --now auditd`
* The `AF UNIX` audisp plugin must be set to **active** in `/etc/audisp/plugins.d/af_unix.conf`. Changing this setting requires a restart of the service: `systemctl restart auditd`

The following system call should be active in the auditd configuration: execve, execveat, fork, vfork, clone, connect, bind.

This can be achieved using the command line:

```
syscall_name_list=(execve execveat fork vfork clone connect bind)

for syscall_name in "${syscall_name_list[@]}" ; do
  echo "Enabling: ${syscall_name}"
  sudo auditctl -a exit,always -F arch=b64 -S "${syscall_name}"
done
```

or with a `10-zeek_agent.rules` file within the `/etc/audit/rules.d` folder:

```
-a exit,always -F arch=b64 -S execve
-a exit,always -F arch=b64 -S execveat
-a exit,always -F arch=b64 -S fork
-a exit,always -F arch=b64 -S vfork
-a exit,always -F arch=b64 -S clone
-a exit,always -F arch=b64 -S connect
-a exit,always -F arch=b64 -S bind
```

**Agent configuration**

The configuration file is located at the following location: `/etc/zeek-agent/config.json`. Comments are **NOT** supported inside this file and should be removed.

```
{
  // Address of the Zeek instance
  "server_address": "127.0.0.1",
  "server_port": 9999,

  // Local folder for the Zeek Agent logs
  "log_folder": "/var/log/zeek",

  // Maximum amount of rows that can be queued for each table.
  // The queue is emptied whenever the table is queried by the
  // Zeek instance. Once the limit is reached, older items are
  // dropped to make room for the new ones.
  "max_queued_row_count": 10000,

  // If osquery support is enabled, this is the Thrift socket for
  // extensions. Inside osquery, it can be configured with the
  // following flag: --extensions_socket=/path/to/socket
  "osquery_extensions_socket": "/var/osquery/osquery.em",

  // List of Zeek groups that are joined on startup
  "group_list": [
    "group0",
    "group1"
  ],

  // Authentication settings, not yet supported by the osquery framework
  "authentication": {
    "certificate_authority": "/path/to/certificate_authority.crt",
    "client_certificate": "/path/to/client_certificate.crt",
    "client_key": "/path/to/client_key.key"
  }
}
```

Sample configuration:
```
{
  "server_address": "127.0.0.1",
  "server_port": 9999,

  "log_folder": "/var/log/zeek",
  "max_queued_row_count": 5000,
  "osquery_extensions_socket": "/var/osquery/osquery.em",

  "group_list": [
    "site01"
  ]
}
```

**Installing Zeek and the Zeek scripts**

Follow the install instructions found at the following repository: [osquery framework](https://github.com/zeek/osquery-framework#prerequisites)

## Running Zeek Agent

Both **Zeek** and **auditd** should be running. If [osquery](https://github.com/osquery/osquery) support was enabled at build time, then it should also be started. Make sure the extensions socket passed to osquery matches the path set in the Zeek Agent configuration.

Here's an example on how to start osquery:

```
osqueryd --verbose --disable_extensions=false --extensions_socket=/var/osquery/osquery.em
```

The above settings can also be specified in the [osquery flagfile](https://osquery.readthedocs.io/en/stable/installation/cli-flags).
