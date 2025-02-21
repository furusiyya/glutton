# Installation

Follow these steps to install Glutton on your system.

## Prerequisites

Ensure you have [Go](https://go.dev/dl/) installed (recommended version: **Go 1.21** or later). In addition, you will need system packages for building and running Glutton:
### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install gcc libpcap-dev iptables
```

### Arch Linux
```bash
sudo pacman -S gcc libpcap iptables
```

### Fedora
```bash
sudo dnf install gcc libpcap-devel iptables
```

## Building Glutton

Clone the repository and build the project:

```bash
git clone https://github.com/mushorg/glutton.git
cd glutton
make build
```

This will compile the project and place the server binary in the `bin/` directory.

## Testing the Installation

```bash
sudo bin/server -i <network_interface>
```

Replace `<network_interface>` (e.g., `eth0`) with the interface you want to monitor. You should see something like the following output in your command line:

```bash

  _____ _       _   _
 / ____| |     | | | |
| |  __| |_   _| |_| |_ ___  _ __
| | |_ | | | | | __| __/ _ \| '_ \
| |__| | | |_| | |_| || (_) | | | |
 \_____|_|\__,_|\__|\__\___/|_| |_|

	
glutton version v1.0.1+d2503ba 2025-02-21T05:48:07+00:00

{"time":"2025-02-21T10:55:22.693830228+05:00","level":"INFO","msg":"Loading configurations from: config/config.yaml","sensorID":"26177d45-24fd-4d59-8406-e8c9b2217689","reporter":"glutton"}

```

## Development Setup

For development, you can use the provided Dev Container configuration. If you’re using VS Code, install the Dev Container extension and open the project inside the container for a Linux-based development environment.
