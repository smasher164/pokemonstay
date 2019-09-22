# Pokémon Stay

This repository holds the source for the Pokémon Stay group project for CS 3250. Local development and builds can be done with
```
$ make run
```
and with the correct credentials, deployment to the server can be done with
```
$ make deploy
```

### Development

Development requires [Docker](https://www.docker.com/) to be installed on your local machine. Additionally, the Makefile assumes that Unix shell commands can be run on your system. This can be updated to accomodate Windows users, but a Unix-like environment would be preferrable.
- MacOS users: Install [Docker Community Edition (CE) for Mac](https://docs.docker.com/v17.12/docker-for-mac/install/)
- Linux users: Install [Docker Community Edition (CE) for your distro](https://docs.docker.com/v17.12/install/#server)
- Windows users: (Please file an issue if you encounter any problems with the process below)
    1. Install the [Windows Subsystem for Linux (WSL)](https://docs.microsoft.com/en-us/windows/wsl/install-win10) to set up a Unix-like environment on your system.
    2. [Install WSL2](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install) for full system-call compatibility.
    3. Install [Docker for WSL2](https://docs.docker.com/docker-for-windows/wsl-tech-preview/).

### Deployment

This repository is set up to deploy on push to master. The deployment process's log can be observed under the "Production Deployment" workflow in the Actions tab of the repo.

The Docker image we are currently using is based on the latest Python 3.8 beta as well as Alpine Linux 3.10. The `stay.service` and `stay.sh` files can be ignored as they are deployment details that already exist on the cloud provider's VM.