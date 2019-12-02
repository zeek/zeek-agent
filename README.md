# zeek-agent

## Building from source

For users that are already familiar with CMake, the project should be easy to build once the required dependencies have been installed and the repository has been cloned with all the submodules. No special steps are required to configure or build the binaries.

Project options have been grouped under the `ZEEK` prefix and will show up in configuration tools such as `ccmake` and `cmake-gui`.

It is also possible to run the following script to configure, build, test and generate the packages: `scripts/ci_entry_point.sh`

**1 - Supported systems**

For development and generating releases, Ubuntu >= 18.04 is currently the only supported distribution

For users, releases will work on any distribution post Ubuntu 16/CentOS 6 as long as the binaries have been generated with the osquery-toolchain.

**2 - Dependencies**
* clang
* libauparse-dev
* libaudit-dev
* libssl-dev

On Ubuntu/Debian-based distributions, the required packages can be installed with the following command:

`sudo apt install clang libauparse-dev libaudit-dev libssl-dev`

**2 - Obtaining the source code**

Clone the repository along with all the necessary submodules: `git clone https://github.com/zeek/osquery-extension --recursive`

If the repository has already been cloned without `--recursive` (or if the repository is being updated with new commits), then the submodules can be updated again with the following commands:

```
git submodule sync --recursive
git submodule update --init --recursive
```

**3 - Building the project**

1. Create and enter the build folder: `mkdir build && cd build`
2. Configure the project: `cmake -DCMAKE_CXX_COMPILER:STRING=clang++ -DCMAKE_C_COMPILER:STRING=clang -DCMAKE_BUILD_TYPE:STRING=Release -DZEEK_AGENT_ENABLE_INSTALL:BOOL=ON /path/to/source/folder`
3. Build the binaries: `cmake --build . -j $(nproc)`
4. Run the tests: `cmake --build . --target zeek_agent_tests -j $(nproc)`
5. Install the binaries (**not yet supported**): `cmake --build . --target install -j $(nproc)`
6. Create packages (**not yet supported**): `cmake --build . --target package -j $(nproc)`

## Configuration

**1 - Audit configuration**

* The auditd daemon must be enabled and running: `systemctl enable --now auditd`
* The `AF UNIX` audisp plugin must be set to **active** in `/etc/audisp/plugins.d/af_unix.conf`. Changing this setting requires a restart of the service: `systemctl restart auditd`

**2 - Agent configuration**

The configuration file is located at the following location: `/etc/zeek-agent/config.json`

A sample configuration follows:

```
{
  "server_address": "127.0.0.1",
  "server_port": 9999,
  "log_folder": "/var/log/zeek",

  "group_list": [
    "group0",
    "group1"
  ],

  "authentication": {
    "certificate_authority": "/path/to/certificate_authority.crt",
    "client_certificate": "/path/to/client_certificate.crt",
    "client_key": "/path/to/client_key.key"
  }
}
```

Please note that the `authentication` object should be omitted for now, as the Zeek scripts are yet to be updated.

**3 - Installing Zeek and the Zeek scripts**

Follow the install instructions found at the following repository: [osquery framework](https://github.com/zeek/osquery-framework#prerequisites)

## Generating distro-independent binaries

It is possible to build the project using the [osquery toolchain](https://github.com/osquery/osquery-toolchain) in order to create binaries that are compatible with any distribution past Ubuntu 16 and CentOS 6.

1. Download the tarball package from the release page
2. Extract it
3. Update the path: `export PATH="/path/to/osquery-toolchain/usr/bin:${PATH}"`

Set the right compiler to CMake by passing the following additional parameters:

```
-DCMAKE_C_COMPILER:PATH=/path/to/osquery-toolchain/usr/bin/clang
-DCMAKE_CXX_COMPILER:PATH=/path/to/osquery-toolchain/usr/bin/clang++
```
