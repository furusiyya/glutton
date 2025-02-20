# Configuration

Glutton’s behavior is controlled by several configuration files written in YAML (and JSON for schema validation). This page details the available configuration options, how they’re loaded, and best practices for customizing your setup.

## Configuration Files

### config/config.yaml

This file holds the core settings for Glutton. Key configuration options include:

- **ports:** Defines the network ports used for traffic interception.
  - **tcp:** The TCP port for intercepted connections (default: `5000`).
  - **udp:** The UDP port for intercepted packets (default: `5001`).
  - **ssh:** Typically excluded from redirection to avoid interfering with SSH (default: `22`).
- **interface:** The network interface Glutton listens on (default: `eth0`).
- **max_tcp_payload:** Maximum TCP payload size in bytes (default: `4096`).
- **conn_timeout:** The connection timeout duration in seconds (default: `45`).
- **confpath:** The directory path where the configuration file resides.
- **producers.enabled:** Boolean flag to enable or disable logging/producer functionality.
- **addresses:** A list of additional public IP addresses for traffic handling.

Example configuration:

```yaml
# config/config.yaml

ports:
  tcp: 5000
  udp: 5001
  ssh: 22
interface: eth0
max_tcp_payload: 4096
conn_timeout: 45
confpath: ./config
producers:
  enabled: true
addresses:
  - 192.168.1.100
  - 10.0.0.1
```

### config/rules.yaml

This file defines the rules that Glutton uses to determine which protocol handler should process incoming traffic.

Key elements include:

**target**: Indicates the protocol handler (e.g., "http", "ftp") to be used.
**conditions**: Define criteria such as source IP ranges or destination ports to match incoming traffic.

Example rule:

```yaml
# config/rules.yaml

- name: "HTTP Traffic"
  target: "http"
  conditions:
    source_ip: "0.0.0.0/0"
    destination_port: 80
```

### config/schema.json
The `schema.json` file is used to validate the structure of your configuration files. It ensures that your configuration adheres to the expected format and data types.

## Configuration Loading Process
Glutton uses the [Viper](https://github.com/spf13/viper) library to load configuration settings. The process works as follows:

- **Default Settings**: Glutton initializes with default values for critical parameters.
- **File-based Overrides**: Viper looks for config.yaml in the directory specified by confpath. If found, the settings from the file override the defaults.
- **Additional Sources**: Environment variables or command-line flags can further override file-based configurations, allowing for flexible deployments.

# Best Practices

- **Backup Your Files**: Always save a backup of your configuration files before making changes.
- **Validate Configurations**: Use YAML validators and the provided JSON schema to ensure your configuration is error-free.
- **Test Changes**: After modifying your configuration, restart Glutton and review the logs to confirm that your changes have been applied as expected.

By understanding and customizing these configuration files, you can tune Glutton to match your network environment and security analysis requirements.
