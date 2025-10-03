# PSPrismaAccessToolkit

Lightweight PowerShell toolkit for troubleshooting Palo Alto Networks Prisma Access / GlobalProtect deployments. Includes helpers for validating SSL decryption behavior, analyzing HAR files, and parsing GlobalProtect logs to formats more administrator friendly.

## Features

- Validate whether a website URL is being decrypted or not
- Parse browser HAR capture files for any web URLs being decrypted
- Extract unique domains from HAR files
- Export TLS/SSL Certificate chain from target website into .CRT files
- Export (certain) GlobalProtect log files to CSV, or an array of PSCustomObjects for further filtering in Powershell
- Small, dependency-free module suitable for automation or interactive use

## Requirements

- PowerShell 5.1 or PowerShell 7+
- Certain functionality requires a local copy of the root certificate used in the SSL Decryption Forward Trust configuration.

## Installation

Manual install:
1. Copy the `PSPrismaAccessToolkit` folder to one of the paths in `$env:PSModulePath`, for example:
   - `%USERPROFILE%\Documents\WindowsPowerShell\Modules\`
   - `%ProgramFiles%\WindowsPowerShell\Modules\`
2. Import the module:
   ```powershell
   Import-Module PSPrismaAccessToolkit
   ```

Alternative Installation:
1. Navigate to the local directory where `PSPrismaAccessToolkit` resides.
2. Import the .psm1 module file
   ```powershell
   Import-Module PSPrismaAccessToolkit.psm1
   ```

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
___Note:___ _This command must be ran from the affected endpoint where decryption might be taking place. It essentially checks for the presence of the provided root certificate in the certificate chain presented by the destination server during TLS negotiation_.

### Analyze a HAR file for hostnames that are being decrypted

Analyzes ".\mycapture.har" and checks if SSL decryption is occurring for each failed HTTP(S) request using the specified root certificate.

```powershell
Test-HarFileForDecryptedUrls -HarFilePath ".\mycapture.har" -RootCertPath ".\root.crt"
```
___Note:___ _This command must be ran from the affected endpoint where decryption might be taking place. It uses a derivative of the above ```Test-SSLDecryption``` command behind the scenes_.

### Get unique domains from a HAR file

Lists all unique domains found in the HAR file "mycapture.har".
```powershell
Get-HarFileUniqueDomains -HarFilePath ".\mycapture.har"
```

### Export Palo Alto/GlobalProtect logs to CSV:

Parses the the PAN***.log files (PanGPS.log, PanGPA.log, etc), includes only entries since the specified date/time, and returns the parsed logs in an array of PSCustomObjects instead of exporting them CSV.

```powershell
Export-PanLogFileToCsv -Path ".\PanGPS.log" -Since "07/30/25 08:55" -ReturnObject
```

___Note:___ This command can parse log files that are in the same log format as PanGPS.log or PanGPA.log. It has only been tested against PanGPS.log and PanGPA.log, though, so results may vary.

### Export SSL certificate chain to CRT files

Export the full SSL/TLS certificate chain presented by a remote host to individual .crt files (Base 64 encoded). Files are written to the current working directory — consider running in a dedicated folder to avoid accidental overwrites.

```powershell
# Simple: export chain for example.com (writes .crt files to current folder)
Export-SSLCertificateChain -Hostname "example.com"

# Use a custom port (e.g. 8443)
Export-SSLCertificateChain -Hostname "internal.site" -Port 8443
```
_Note: Filenames are created from the common name of the certificate._

## Module commands

Implemented functions (confirm with Get-Command):
- Test-SSLDecryption
- Test-HarFileForDecryptedUrls
- Get-HarFileUniqueDomains
- Export-PanLogFileToCsv
- Export-SSLCertificateChain

## Contributing

- Fork the repository, add tests and documentation, then open a PR.
- Follow the coding style and include examples for new functions.

## License

See the included LICENSE file for license terms.

## Disclaimer
1. Certain commands in this module are relient on Palo Alto features that might be subject to change, such as log formats. It's entirely possible that changes made by Palo Alto might break the functionality of the commands provided.
2. This repository is not owned, operated, or officially maintained by Palo Alto Networks. Palo Alto Networks has no formal association with this repository, Powershell module, or any of the functionality it may provide. 

## Support / Issues

Submit issues within the [GitHub Repository](https://github.com/tjobarow/PSPrismaAccessToolkit/issues).

## Author
Thomas Obarowski
- **[Github](https://github.com/tjobarow)**
- **[LinkedIn](https://www.linkedin.com/in/tjobarow/)**
