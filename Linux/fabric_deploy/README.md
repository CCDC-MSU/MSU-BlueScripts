# CCDC Hardening Deployment Framework

This repository contains a Python Fabric-based automation framework designed for the rapid deployment of security hardening configurations, tailored for Collegiate Cyber Defense Competition (CCDC) scenarios. It allows for automated discovery of system information and deployment of hardening modules across multiple hosts.

## Features

*   **Automated System Discovery**: Automatically fingerprints target systems to identify OS, users, services, and more.
*   **Modular Hardening**: A flexible, module-based architecture for applying specific hardening configurations.
*   **OS-Aware Deployment**: Automatically selects the appropriate scripts and configurations based on the detected OS family.

## Getting Started

This project is designed to be run from a central "jumpbox" or administrative machine. The `bootstrap_onto_jumpbox.sh` script is provided to quickly set up the environment.

### Prerequisites

*   A Linux-based machine to act as the jumpbox.
*   `git`, `python3`, and `python3-pip` installed on the jumpbox.

### Setup

1.  **Clone the Repository**:
    ```bash
    git clone <your-repository-url> ccdc-scripts
    cd ccdc-scripts/fabric_deploy
    ```

2.  **Run the Bootstrap Script**:
    The `bootstrap_onto_jumpbox.sh` script will:
    *   Install necessary system packages.
    *   Create a Python virtual environment.
    *   Install the required Python dependencies from `requirements.txt`.
    *   Create initial configuration files (`config.yaml`, `hosts.txt`).
    *   Generate an SSH key if one doesn't exist.

    To run the script:
    ```bash
    ./bootstrap_onto_jumpbox.sh
    ```

3.  **Activate the Virtual Environment**:
    ```bash
    source activate.sh
    ```

4.  **Configure the Framework**:
    *   **`hosts.txt`**: Add the IP addresses or hostnames of your target machines to this file, along with their credentials.
    *   **`users.json`**: If you are using the `user_hardening` module, configure your authorized users in this file.

## Usage

All commands are run from the `Linux` directory using `fab`.

### Basic Operations

*   **Test Connection to a Host**:
    ```bash
    fab test-connection --host <ip-address>
    ```

*   **Discover a Single Host**:
    ```bash
    fab discover --host <ip-address>
    ```

*   **Discover All Hosts in hosts.txt**:
    ```bash
    fab discover-all
    ```
    Runs in parallel. Per-host logs are written to `logs/discover-all/<host>/<timestamp>.log`.

*   **Run the Full Hardening Pipeline**:
    This command will discover all hosts in `hosts.txt` and then apply the appropriate hardening modules.
    ```bash
    fab harden
    ```
    Runs in parallel. Per-host logs are written to `logs/harden/<host>/<timestamp>.log`.

*   **Dry Run**:
    To see what changes would be made without actually applying them, use the `--dry-run` flag.
    ```bash
    fab harden --dry-run
    ```

### Advanced Usage

*   **Deploy Specific Modules**:
    ```bash
    fab harden --modules=ssh_hardening,firewall_hardening
    ```

*   **Deploy Scripts by Category**:
    ```bash
    fab deploy-scripts --categories=users,ssh,firewall
    ```

*   **Run an Arbitrary Local Script on All Targets**:
    ```bash
    fab run-script --file /path/to/script.sh
    ```
    Runs in parallel across hosts. Output for each host is written under
    `script_outputs/<script_name>/` in this directory, and a per-host summary with return
    codes is printed at the end. Use `--output-dir` to change the local output folder.
    Optional flags: `--sudo=False`, `--timeout=120`, `--hosts-file=hosts.txt`, `--shell=sh`, `--dry-run`.

## Module Testing

This framework includes a powerful testing system for developing and validating individual hardening modules.

*   **List Available Modules**:
    ```bash
    fab list-modules
    ```

*   **Test a Single Module (in dry-run mode)**:
    ```bash
    fab test-module --module=user_hardening
    ```

*   **Test a Module in Live Mode**:
    Use the `--live` flag to apply the changes.
    ```bash
    fab test-module --module=firewall_hardening --live
    ```

*   **Test All Modules**:
    ```bash
    fab test-all-modules
    ```

## User Hardening

The `user_hardening` module is one of the most critical components of this framework. It provides a comprehensive solution for managing user accounts and `sudo` privileges. For more detailed information, please see the `README_user_hardening.md` file.

## Architecture

*   **`fabfile.py`**: The main entry point for all Fabric tasks.
*   **`utilities/`**: This directory contains the core logic of the framework.
    *   **`discovery.py`**: The system discovery engine.
    *   **`deployment.py`**: The hardening deployment engine.
    *   **`models.py`**: Data models for server and user information.
    *   **`modules/`**: The directory containing all the individual hardening modules.

## Contributing

To add a new hardening module:

1.  Create a new Python file in the `fabric_deploy/utilities/modules/` directory.
2.  In your new file, create a class that inherits from `HardeningModule`.
3.  Implement the `get_name` and `get_commands` methods.
4.  Add your new module to the `__init__.py` file in the `modules` directory.
5.  Test your module using the module testing framework.
