# Ubuntu Reconnaissance Tool

**Author:** Nathan Peck (nsp7941@rit.edu)

This is a python tool used to gather system and network information from Ubuntu machines and send results to a remote server.

## Features
- Scans listening ports using `ss`
- Performs Nmap scans
- Lists scheduled tasks
- Lists local users and groups
- Checks file permissions
- Displays firewall rules
- Automatically sends updated results every 5 minutes

## Installation

Deploy the scanner to Linux clients using Ansible:

```bash
ansible-playbook -i inventory.ini deploy.yml
```

## Usage

Start the receiver on the server:

```bash
python3 receiver.py --listen 10.111.11.x --port 8450
```

The clients automatically send their scan results to the server. Use the numbered server menu to view the results for each client.

## Requirements
- Network connectivity and access between clients and server
- Other reqs are installed by running ansible script


