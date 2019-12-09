# zeek-agent

The Zeek Agent is an endpoint monitoring tool that reports socket and process events to a [Zeek](https://zeek.org) server instance. Event data is captured from Audit using the Unix domain socket plugin that comes with Audisp, and is then presented as a SQL database using SQLite virtual tables. It is optionally possible to enable osquery support, allowing Zeek to access all its non-evented tables.

## Build types

The Zeek agent can be built in three different configurations, with or without [osquery](https://github.com/osquery/osquery) support.

1. Using the system compiler, generating binaries that will probably only work on the distribution used to build the release.
2. With the [osquery-toolchain](https://github.com/osquery/osquery-toolchain), generating binaries that will work on any distribution shipping a glibc version that is greater than or equal to 2.12 (CentOS 6/Ubuntu 16.04 and above).
3. Under the osquery source tree, enabling support for all the non-evented tables such as `processes` and `interfaces`. This will also automatically enable the osquery-toolchain.

When generating redistributable packages, it is best to use build types 2 and 3. Distribution maintainers who wish to use system dependencies (when possible) may prefer going with option 1.

## Building from source

**Introduction**

For users that are already familiar with CMake, the project should be easy to build once the required dependencies have been installed and the repository has been cloned with all the submodules. No special steps are required for the configure and build steps.

Project options have been grouped under the `ZEEK` prefix and will show up in configuration tools such as `ccmake` and `cmake-gui`.

It is also possible to run the following script to configure, build, test and generate the packages: `scripts/build_release.sh`

**Dependencies**

When building with the system compiler, the following packages are needed: `clang`, `libssl-dev`. There are no special requirements when building with the osquery-toolchain. For the osquery-enabled build, Flex and Bison should be installed.

In order to successfully create packages, the `dpkg` and `rpm` binaries should be installed.

**Obtaining the source code**

Clone the repository along with all the necessary submodules: `git clone https://github.com/zeek/osquery-extension --recursive`

If the repository has already been cloned without `--recursive` (or if the repository is being updated with new commits), then the submodules can be updated again with the following commands:

```
git submodule sync --recursive
git submodule update --init --recursive
```

**Selecting the build type**

*Note: Only add the parameters from one of the three alternatives!*

Standalone build (i.e. no osquery support)

1. When using the system compiler, clang is recommended. Add the `-DCMAKE_CXX_COMPILER:STRING=clang++ -DCMAKE_C_COMPILER:STRING=clang` parameters to the cmake configuration command.
2. When the osquery-toolchain is used instead, add the toolchain path: `-DZEEK_AGENT_TOOLCHAIN_PATH:PATH=/path/to/toolchain`

Full build (i.e. with support for osquery tables)

3. Create a symbolic link of the Zeek agent repository inside the `external` folder under the osquery source tree.

**Building the project**

1. Create and enter the build folder: `mkdir build && cd build`
2. Configure the project: `cmake <additional parameters, see the point above> -DCMAKE_BUILD_TYPE:STRING=Release -DZEEK_AGENT_ENABLE_INSTALL:BOOL=ON /path/to/source/folder`
3. Build the binaries: `cmake --build . -j $(nproc)`
4. Run the tests: `cmake --build . --target zeek_agent_tests -j $(nproc)`
5. Install the binaries: `cmake --build . --target install -j $(nproc)`
6. Create the packages: `cmake --build . --target package -j $(nproc)`

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
