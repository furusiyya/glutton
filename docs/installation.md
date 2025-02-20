# Installation

Follow these steps to install Glutton on your system.

## Prerequisites

Ensure you have Go installed (recommended version: **Go 1.21** or later). In addition, you will need system packages for building and running Glutton:

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

## Development Setup

For development, you can use the provided Dev Container configuration. If you’re using VS Code, install the Dev Container extension and open the project inside the container for a Linux-based development environment.

