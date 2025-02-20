# Deployment

Glutton can be deployed in various environments. Here are the most common deployment methods:

## Running the Server Directly

After building the project, you can run the server with:

```bash
sudo bin/server -i <network_interface> -l /var/log/glutton.log -d true
```

Replace `<network_interface>` (e.g., `eth0`) with the interface you want to monitor. The command starts the Glutton server, which sets up TCP/UDP listeners and applies iptables rules for transparent proxying.

**Configuration:**  
Before deployment, ensure that your configuration files are properly set up. For detailed instructions on configuring Glutton (including adjustments to `config/config.yaml` and `config/rules.yaml`), please refer to the [Configuration](configuration.md) page.

## Docker Deployment

Glutton provides a Dockerfile for containerized deployment. To deploy using Docker:

1. **Build the Docker Image:**  
   
    ```
    docker build -t glutton .
    ```

2. **Run the Container:**  
   
    ```
    docker run --rm --cap-add=NET_ADMIN -it glutton
    ```

The Docker container is preconfigured with the necessary dependencies (iptables, libpcap, etc.) and copies the configuration and rules files into the container.

