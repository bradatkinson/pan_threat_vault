# pan_threat_vault

The purpose of this script is to pull the Threat Vault info from a PAN device and parse into a CSV file.

## Built With

[Docker](https://www.docker.com/products/docker-desktop)  
[Palo Alto Networks PAN-OS SDK for Python](https://github.com/PaloAltoNetworks/pan-os-python)  
[Arrow](https://arrow.readthedocs.io/en/latest/)

## Deployment

All files within the folder should be deployed in the same directory for proper file execution.

## Prerequisites

Update `config.py` file with correct values before operating.

If running the script multiple times, uncomment the following lines in the Dockerfile to only get updates.
```
COPY ./data/vulnerability.json data/
COPY ./data/phone-home.json data/
```

## Operating

From the CLI, change directory into the folder containing the files.  The following command will execute the script:

```bash
docker-compose up
```

After the script has completed or if the script needs to be reran, issue the following command:

```bash
docker-compose down --rmi all
```

The CSV file will be found in the data folder.

## Changelog

See the [CHANGELOG](CHANGELOG.md) file for details

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
