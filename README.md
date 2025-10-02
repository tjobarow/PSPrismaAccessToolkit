# PSPrismaAccessToolkit

Lightweight PowerShell toolkit for troubleshooting Palo Alto Networks Prisma Access / GlobalProtect deployments. Includes helpers for validating SSL decryption behavior, analyzing HAR files, and parsing GlobalProtect logs to formats more administrator friendly.

## Features

- Validate whether a website URL is being decrypted or not
- Parse browser HAR capture files for any web URLs being decrypted
- Extract unique domains from HAR files
- Export (certain) GlobalProtect log files to CSV, or an array of PSCustomObjects for further filtering in Powershell
- Small, dependency-free module suitable for automation or interactive use

## Requirements

- PowerShell 5.1 or PowerShell 7+
- Module directory placed on a path listed in $env:PSModulePath

## Installation

Manual install:
1. Copy the `PSPrismaAccessToolkit` folder to one of the paths in `$env:PSModulePath`, for example:
   - `%USERPROFILE%\Documents\WindowsPowerShell\Modules\`
   - `%ProgramFiles%\WindowsPowerShell\Modules\`
2. Import the module:
   ```powershell
   Import-Module PSPrismaAccessToolkit
   ```

(Optionally package and publish to an internal PowerShell Gallery for easier distribution.)

## Quick examples

Import module and list commands:
```powershell
Import-Module PSPrismaAccessToolkit
Get-Command -Module PSPrismaAccessToolkit
# Get help for a specific command
Get-Help -Name Test-SSLDecryption -Full
```

### Test SSL decryption for a target hostname:

Checks if the root certificate at "C:\certs\myroot.crt" is present in the certificate chain for "example.com" on port 443. 
```powershell
Test-SSLDecryption -hostname "example.com" -RootCertPath "C:\certs\myroot.crt"
```

### Analyze a HAR file for hostnames that are being decrypted

Analyzes ".\mycapture.har" and checks if SSL decryption is occurring for each failed HTTP(S) request using the specified root certificate.

```powershell
Test-HarFileForDecryptedUrls -HarFilePath ".\mycapture.har" -RootCertPath ".\root.crt"
```

### Get unique domains from a HAR file

Lists all unique domains found in the HAR file "mycapture.har".
```powershell
Get-HarFileUniqueDomains -Path ".\mycapture.har"
```

### Export Palo Alto/GlobalProtect logs to CSV:

Parses the PanGPS.log file, includes only entries since the specified date/time, and returns the parsed logs in an array of PSCustomObjects instead of exporting them CSV.

```powershell
Export-PanLogFileToCsv -Path ".\PanGPS.log" -Since "07/30/25 08:55" -ReturnObject
```

## Module commands

Implemented functions (confirm with Get-Command):
- Test-SSLDecryption
- Test-HarFileForDecryptedUrls
- Get-HarFileUniqueDomains
- Export-PanLogFileToCsv

## Contributing

- Fork the repository, add tests and documentation, then open a PR.
- Follow the coding style and include examples for new functions.

## License

See the included LICENSE file for license terms.

## Support / Issues

Submit issues within the [GitHub Repository](https://github.com/tjobarow/PSPrismaAccessToolkit/issues).

## Author
Thomas Obarowski
- **Github**: tjobarow
- **Email**: tjobarow@gmail.com