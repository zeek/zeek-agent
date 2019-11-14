# zeek-agent


## Sample configuration file
```
/etc/zeek-agent/config.json
```

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
