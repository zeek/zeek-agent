# zeek-agent

The Zeek Agent is an endpoint monitoring tool that reports socket and process events to a [Zeek](https://zeek.org) server instance. Event data is captured from Audit using the Unix domain socket plugin that comes with Audisp, and is then presented as a SQL database using SQLite virtual tables. It is optionally possible to enable osquery support, allowing Zeek to access all its non-evented tables.

Pre-built packages are available in the [releases page](https://github.com/zeek/osquery-extension/releases).

## Documentation

The documentation has been moved to the [Zeek Agent Wiki](https://github.com/zeek/osquery-extension/wiki), and contains guides on building, configuring and extending the Zeek Agent project.

For convenience, the build and configuration guides can be accessed from the following links:
- [Build Guide](https://github.com/zeek/osquery-extension/wiki/Build-Guide)
- [Configuration Guide](https://github.com/zeek/osquery-extension/wiki/Configuration-Guide)
