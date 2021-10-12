# pan_threat_vault

The purpose of this script is to pull the Threat Vault info from a PAN device and parse into a CSV file.

## Built With

[Palo Alto Networks PAN-OS SDK for Python](https://github.com/PaloAltoNetworks/pan-os-python)  
[Arrow](https://arrow.readthedocs.io/en/latest/)

## Deployment

All files within the folder should be deployed in the same directory for proper file execution.

## Prerequisites

Update `config.py` file with correct values before operating.

## Operating

The below command will execute the script.

```bash
python pan_threat_vault.py
```

## Changelog

See the [CHANGELOG](CHANGELOG.md) file for details

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
