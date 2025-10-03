<#PSScriptInfo

.SCRIPTNAME    PSPrismaAccessToolkit.psm1
.VERSION       1.0

.AUTHOR        Thomas Obarowski (tjobarow@gmail.com)

.DATE          2025/09/10 12:54:56

.COMPANYNAME   N/A

.COPYRIGHT     MIT License

.TAGS          PrismaAccess, PaloAlto, SSL, Decryption, GlobalProtect, HAR, Automation, Troubleshooting

.LICENSEURI    https://github.com/tjobarow/PSPrismaAccessToolkit/blob/main/LICENSE
.PROJECTURI    https://github.com/tjobarow/PSPrismaAccessToolkit

.SYNOPSIS
    A collection of PowerShell functions for troubleshooting Prisma Access deployments, including SSL decryption validation, HAR file analysis, and GlobalProtect log parsing.

.DESCRIPTION
    This module provides functions to:
    - Test if Prisma Access is decrypting SSL traffic for a given host.
    - Analyze HAR files to determine SSL decryption status for failed requests.
    - Extract unique domains from HAR captures.
    - Parse and export GlobalProtect VPN client logs for further analysis.

.EXAMPLE
    Test-SSLDecryption -hostname "outlook.com"
    Test-SSLDecryption -hostname "outlook.com" -port 443 -RootCertPath ".\root.crt"

.EXAMPLE
    Test-HarFileForDecryptedUrls -HarFilePath ".\mycapture.har" -RootCertPath ".\root.crt"

.EXAMPLE
    Get-HarFileUniqueDomains -HarFilePath ".\mycapture.har"

.EXAMPLE
    Export-PanLogFileToCsv -Path ".\PanGPS.log"
    Export-PanLogFileToCsv -Path ".\PanGPS.log" -Since "07/30/25 08:55" -ReturnObject

.LINK
    https://github.com/tjobarow/Palo-Alto-Prisma-Access-Powershell-Toolkit

#>


function Test-SSLDecryption {
    <#
    .SYNOPSIS
        Tests if SSL decryption is occurring by checking if a specified root certificate is present in the certificate chain presented by a remote host.

    .DESCRIPTION
        The Test-SSLDecryption function connects to a specified hostname and port using SSL/TLS, retrieves the server's certificate chain, and checks if the provided root certificate is present in the chain. 
        This can be used to determine if SSL decryption (such as by Prisma Access) is being performed, as the presence of the root certificate in the chain indicates interception.

    .PARAMETER hostname
        The DNS name or IP address of the remote host to test SSL decryption against. This parameter is mandatory.

    .PARAMETER RootCertPath
        The file path to the root certificate (in .crt format) to check for in the server's certificate chain. Defaults to ".\root.crt" if not specified.

    .PARAMETER port
        The TCP port to connect to on the remote host. Defaults to 443.

    .EXAMPLE
        Test-SSLDecryption -hostname "example.com" -RootCertPath "C:\certs\myroot.crt"

        Checks if the root certificate at "C:\certs\myroot.crt" is present in the certificate chain for "example.com" on port 443.

    .EXAMPLE
        Test-SSLDecryption -hostname "internal.site" -port 8443

        Checks if the default root certificate ".\root.crt" is present in the certificate chain for "internal.site" on port 8443.

    .NOTES
        - Requires PowerShell to run on Windows with access to .NET classes.
        - Useful for troubleshooting SSL decryption by security appliances such as Prisma Access.
        - The function outputs a message indicating whether the root certificate is present in the chain.

    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$hostname,
        [Parameter(Mandatory = $false)]
        [string]$RootCertPath = ".\root.crt",
        [int]$port = 443
    )
    

    if ( -not (Test-Path $RootCertPath)) {
        throw "The value provided for -RootCertPath is not valid, or the default value of 'root.crt' does not exist at the specified path: `n $($RootCertPath)"
    } 
    try {
        # Load the provided root cert from the file system. If this cert is in
        # chain presented by the website, decryption is happening
        $ParamRootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (Get-Item $RootCertPath).FullName
    }
    catch {
        throw "An error was raised while attempting to load root certificate file: $($RootCertPath)"
    }

    try {
        # Defining a TCP client that will connect to the hostname/port provided

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient($hostname, $port)
        }
        catch {
            if ($_.Exception.Message -like "*No such host is known*") {
                throw "The hostname provided ($($hostname)) could not be resolved via DNS. Please check the hostname and try again."
            }
            else {
                $($_.Exception.Message)
                throw "A generic error was raised while establishing a TCP connect with the provided hostname ($($hostname))"
                
            }
        }
        
        
        #Empty script-scoped certs list will later be set to list of certs
        # provided by the website URL
        $script:ChainCerts = @()

        <#
        Defining a callback function that will enumerate the cert chain 
        provided by the website's SSL stream, and save each cert to a locally
        scoped list. Then, modify the script scoped "certs" variable to
        save the list outside the callback function scope
        #> 
            
        $callback = {
            param(
                $senderObj,
                $certificate, 
                $chain, 
                $sslPolicyErrors
            )
            $certificates = @()
            foreach ($element in $chain.ChainElements) {
                <#$certificates += [PSCustomObject]@{
                    SubjectName = $element.SubjectName
                    Issuer = $element.Issuer
                }#>
                $certificates += [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($element.Certificate.RawData)
            }

            Set-Variable ChainCerts -Value $certificates -Scope Script
            return $true
        }
        <#
         Create an SSL stream using the TCP client, provide False to close the
         stream after the provided callback is function is complete
        #>
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(), $false, $callback
        )
        
        # This initiates the SSL connection with the server hostname provided
        $sslStream.AuthenticateAsClient($hostname)

        $ParamRootCertPresentInChain = $false
        foreach ($cert in $script:ChainCerts) {
            if ($cert.SerialNumber -eq $ParamRootCert.SerialNumber) {
                $ParamRootCertPresentInChain = $true
            }
        }

        if ($ParamRootCertPresentInChain) {
            Write-Host "Prisma Access is trying to decrypt $($hostname)! Provided root certificate $($ParamRootCert.Subject) is present in certificate chain!" -BackgroundColor DarkRed -ForegroundColor White
        }
        else {
            Write-Host "Prisma Access is NOT trying to decrypt $($hostname). Provided root certificate $($ParamRootCert.Subject) is NOT present in certificate chain!" -BackgroundColor DarkGreen -ForegroundColor White
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-SslDecryptionHarHelper {

    param (
        [Parameter(Mandatory = $true)]
        [string]$hostname,
        [Parameter(Mandatory = $false)]
        [string]$RootCertPath = ".\root.crt",
        [int]$port = 443
    )
    
    if ( -not (Test-Path $RootCertPath)) {
        throw "The value provided for -RootCertPath is not valid, or the default value of 'root.crt' does not exist at the specified path: `n $($RootCertPath)"
    } 
    try {
        # Load the provided root cert from the file system. If this cert is in
        # chain presented by the website, decryption is happening
        $ParamRootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (Get-Item $RootCertPath).FullName
    }
    catch {
        throw "An error was raised while attempting to load root certificate file: $($RootCertPath)"
    }

    try {
        # Defining a TCP client that will connect to the hostname/port provided
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient($hostname, $port)
        }
        catch {
            if ($_.Exception.Message -like "*No such host is known*") {
                throw "The hostname provided ($($hostname)) could not be resolved via DNS. Please check the hostname and try again."
            }
            else {
                $($_.Exception.Message)
                throw "A generic error was raised while establishing a TCP connect with the provided hostname ($($hostname))"
                
            }
        }
        
        #Empty script-scoped certs list will later be set to list of certs
        # provided by the website URL
        $script:ChainCerts = @()

        <#
        Defining a callback function that will enumerate the cert chain 
        provided by the website's SSL stream, and save each cert to a locally
        scoped list. Then, modify the script scoped "certs" variable to
        save the list outside the callback function scope
        #> 
            
        $callback = {
            param(
                $senderObj,
                $certificate, 
                $chain, 
                $sslPolicyErrors
            )
            $certificates = @()
            foreach ($element in $chain.ChainElements) {
                $certificates += [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($element.Certificate.RawData)
            }
            Set-Variable ChainCerts -Value $certificates -Scope Script
            return $true
        }
        <#
         Create an SSL stream using the TCP client, provide False to close the
         stream after the provided callback is function is complete
        #>
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(), $false, $callback
        )
        
        # This initiates the SSL connection with the server hostname provided
        $sslStream.AuthenticateAsClient($hostname)

        $ParamRootCertPresentInChain = $false
        foreach ($cert in $script:ChainCerts) {
            if ($cert.SerialNumber -eq $ParamRootCert.SerialNumber) {
                $ParamRootCertPresentInChain = $true
            }
        }
        return $ParamRootCertPresentInChain       
    }
    catch {
        Write-Host $_.Exception.Message
        throw "Error while attempting to test SSL decryption towards $($hostname):$($port)"
    }
}

function Test-HarFileForDecryptedUrls {
    <#
    .SYNOPSIS
        Tests if Prisma Access SSL decryption is occurring for failed HTTP(S) requests in a HAR file.

    .DESCRIPTION
        The Test-HarFileForDecryptedUrls function analyzes a HAR (HTTP Archive) file, identifies all HTTP(S) requests with non-successful response codes (outside the 200–399 range), and checks if SSL decryption is being performed for each unique domain by verifying the presence of a specified root certificate in the server's certificate chain.
        This is useful for troubleshooting SSL decryption issues and validating whether Prisma Access is intercepting traffic for problematic URLs.

    .PARAMETER HarFilePath
        The file path to the HAR file to analyze.

    .PARAMETER RootCertPath
        The file path to the root certificate (in .crt format) to check for in the server's certificate chain. Defaults to "root.crt" if not specified.

    .EXAMPLE
        Test-HarFileForDecryptedUrls -HarFilePath ".\mycapture.har" -RootCertPath ".\root.crt"

        Analyzes ".\mycapture.har" and checks if SSL decryption is occurring for each failed HTTP(S) request using the specified root certificate.

    .NOTES
        - Requires PowerShell and access to .NET classes.
        - Useful for validating SSL decryption by Prisma Access for failed requests captured in HAR files.
        - Outputs a formatted table showing the decryption status for each tested URL.

    #>
    param (
        [string]$HarFilePath,
        [string]$RootCertPath = "root.crt"
    )

    if (-not(Test-Path $HarFilePath)) {
        throw "No HAR file located at $($HarFilePath)"
        exit 1
    }

    $HARFileContents = Get-Content -Path $HarFilePath -ErrorAction Stop | ConvertFrom-Json
    $HAREntriesWithNonSuccessResponse = $HARFileContents.log.entries | Where-Object {
        ($null -ne $_.response -and $null -ne $_.response.status) -and `
        ($_.response.status -lt 200 -or $_.response.status -gt 399) -and `
        ($null -ne $_.request -and $null -ne $_.request.url) -and `
        ($_.request.url -like "http*")
    }
    Write-Host "Found $($HAREntriesWithNonSuccessResponse.Count) HTTP requests that were not successful within HAR capture."

    $Results = @()
    foreach ($entry in $HAREntriesWithNonSuccessResponse) {
        Write-Host "Testing URL $($entry.request.url)"
        if ($entry.request.url -like "http://*") { $port = 80 }
        else { $port = 443 }
        $domain = ($entry.request.url -replace '^https?://(www\.)?', '') -replace '/.*$', ''
        $Decrypted = Test-SslDecryptionHarHelper -hostname $domain -port $port
        $Results += [pscustomobject]@{
            OriginalURL        = $entry.request.url
            OriginalStatusCode = $entry.response.status
            DomainNameTested   = $domain
            IsDecrypted        = $Decrypted
            Timestamp          = $entry.startedDateTime
        }
    }

    $Results | Format-Table -AutoSize Timestamp, DomainNameTested, @{
        Label      = "Is Prisma Decrypting URL?"
        Expression = 
        {
            switch ($_.IsDecrypted) {
                $false { $color = '32'; break }
                $true { $color = '31'; break }
                default { $color = "0" }
            }
            $e = [char]27
            "$e[${color}m$($_.IsDecrypted)${e}[0m"
        }
    }, @{
        Label      = "URL Within HAR"
        Expression = { 
            if ($_.OriginalURL.Length -gt 60) { 
                $_.OriginalURL.Substring(0, 57) + "..." 
            }
            else { 
                $_.OriginalURL
            } 
        }
    }, @{
        Label      = "Response Status Code within HAR"
        Expression = 
        {
            if ($_.OriginalStatusCode -eq 0) { $color = '32' }
            else { $color = '31' }
            $e = [char]27
            "$e[${color}m$($_.OriginalStatusCode)${e}[0m"
        }
    }
}

function Get-HarFileUniqueDomains {
    <#
    .SYNOPSIS
        Extracts and lists all unique domain names from a HAR (HTTP Archive) file.

    .DESCRIPTION
        The Get-HarFileUniqueDomains function parses a HAR file, extracts all URLs from the HTTP requests, and returns a sorted list of unique domain names found in the file.
        This is useful for quickly identifying which domains are present in a web traffic capture.

    .PARAMETER HarFilePath
        The file path to the HAR file to analyze.

    .EXAMPLE
        Get-HarFileUniqueDomains -HarFilePath ".\mycapture.har"

        Lists all unique domains found in the HAR file "mycapture.har".

    .NOTES
        - Requires PowerShell and access to .NET classes.
        - Useful for summarizing domains present in a HAR capture.
        - Outputs the list of domains in a formatted table.

    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$HarFilePath
    )

    if (-not(Test-Path $HarFilePath)) {
        throw "No HAR file located at $($HarFilePath)"
        exit 1
    }

    $HARFileContents = Get-Content -Path $HarFilePath -ErrorAction Stop | ConvertFrom-Json
    $HARFileUniqueUrls = $HARFileContents.log.entries | 
        Select-Object -ExpandProperty request |
        Select-Object -ExpandProperty url |
        ForEach-Object {
            try {
                ([System.Uri]$_).Host
            }
            catch {
                $null
            }
        } |
        Where-Object { $null -ne $_ } |
        Sort-Object -Unique
    Write-Host "Found $($HARFileUniqueUrls.Count) unique domains in the HAR file:"

    $HARFileUniqueUrls | Format-Table -AutoSize
}

function Export-PanLogFileToCsv {
    <#
    .SYNOPSIS
        Parses certain GlobalProtect log files and exports the structured log 
        entries to a CSV file, or returns them as a list of PsCustomObjects.

    .DESCRIPTION
        The Export-PanLogFileToCsv function reads a Palo Alto Networks GlobalProtect 
        log file, parses each log entry using regular expressions, and extracts key 
        fields such as timestamp, log level, process/thread IDs, and message content.
        
        It will only work on GlobalProtect log files formatted LIKE the logs in
        PanGPS.log, or PanGPA.log, e.g
        (P7255-T15641)Dump (1010): 09/03/99 00:05:03:207 HandleDnsCallBack enter...
        (P7255-T15641)Dump (1055): 09/03/99 00:05:03:207 HandleDnsCallBack isPv6=0, from virtual interace=0
        
        It supports filtering logs by a specified date/time, limiting the number of parsed lines for testing, and optionally returning the parsed objects instead of exporting to CSV.
        This function is useful for analyzing VPN client logs, troubleshooting issues, and converting logs into a format suitable for further analysis in Excel or other tools.

    .PARAMETER Path
        The file path to the PanGPS/PanGPA.log file to parse. This parameter is mandatory.

    .PARAMETER Since
        (Optional) Only include log entries with a timestamp greater than or equal to this date/time. Accepts any valid PowerShell datetime string.

    .PARAMETER ReturnObject
        (Optional) If specified, returns the parsed log entries as objects instead of exporting to a CSV file.

    .PARAMETER TestingMode
        (Optional) If specified, limits parsing to the first 10,000 log lines for faster testing.

    .EXAMPLE
        Export-PanLogFileToCsv -Path ".\PanGPA.log"

        Parses the PanGPA.log file and exports all parsed log entries to a CSV file in the current directory.

    .EXAMPLE
        Export-PanLogFileToCsv -Path ".\PanGPS.log" -Since "07/30/25 08:55" -ReturnObject

        Parses the PanGPS.log file, includes only entries since the specified date/time, and returns the parsed objects instead of exporting to CSV.

    .NOTES
        - Requires PowerShell and access to .NET classes.
        - Useful for troubleshooting and analyzing GlobalProtect VPN client logs.
        - The output CSV file is named based on the log file and current date/time.

    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [string]$Since,
        [switch]$ReturnObject,
        [switch]$TestingMode
    )

    $ErrorActionPreference = "Stop"

    # SET UP NECESSARY VARIABLES
    $PanGpsLogHeaderRegex = '^\((P\d{1,6})-(T\d{1,8})\)(Dump|Debug|Info|Error)\s*\(\s*(\d{1,6})\s*\):\s(\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d:\d{1,3})'
    $PanGpsLogLineRegex = '^\((P\d{1,6})-(T\d{1,8})\)(Dump|Debug|Info|Error)\s*\(\s*(\d{1,6})\s*\):\s(\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d:\d{1,3})\s(.*)$'
    $ValidLogLevels = @{
        Info     = 20
        Warning  = 30
        Error    = 40
        Critical = 50
        Dump     = 5
        Debug    = 10
    }

    if (-not(Test-Path $path)) {
        throw "No PanGPS.log file located at $($Path)"
    }

    if ($Since) {
        try {
            $SinceDateTime = [datetime]$Since
        }
        catch {
            Write-Host "Could not parse Since $($Since) to datetime. Please provide a valid date/time format (e.g 07/30/25 08:55)"
        }
    }

    $LogFileName = (Get-Item -Path $Path).Name.Split(".")[0]
    $RawLogEntries = Get-Content -Path $Path
    Write-Host "Loaded $($RawLogEntries.Count) lines from $Path"

    $ParsedLogEntries = @()
    $LineNumber = 0
    $CurrentEntry = $null

    for ($i = 0; $i -lt $RawLogEntries.Count; $i++) {
        if ($TestingMode -and ($LineNumber -gt 10000)) {
            break
        }
        $line = $RawLogEntries[$i]
        if ($line -match $PanGpsLogHeaderRegex) {
            # If we parsed a log line in previous iteration
            if ($CurrentEntry) {
                $ParsedLogEntries += $CurrentEntry
            }
            $LineNumber++
            $CurrentEntry = [pscustomobject]@{
                LineNumber          = $LineNumber
                RawText             = $line
                ProcessId           = $null
                ThreadId            = $null
                ProcessAndThreadIds = $null
                LogLevel            = $null
                LogLevelValue       = $null
                DebugCode           = $null
                Timestamp           = $null
                Message             = $null
            }

            if ($line -match $PanGpsLogLineRegex) {
                $CurrentEntry.ProcessId = $matches[1]
                $CurrentEntry.ThreadId = $matches[2]
                $CurrentEntry.ProcessAndThreadIds = "$($matches[1]+"-"+$matches[2])"
                $CurrentEntry.LogLevel = $matches[3]
                $CurrentEntry.LogLevelValue = $ValidLogLevels[$matches[3]]
                $CurrentEntry.DebugCode = $matches[4]
                $adjusted_timestamp = $matches[5] -replace ':(\d{3})$', '.${1}'
                $CurrentEntry.Timestamp = [datetime]::ParseExact($adjusted_timestamp, 'MM/dd/yy HH:mm:ss.fff', $null)
                $CurrentEntry.Message = $matches[6]
            }
            else {
                Write-Host "Log line did not match regex!"
                Write-Host $line
            }
            Write-Host "$($LineNumber): $line"
        }
        elseif ($CurrentEntry) {
            $CurrentEntry.RawText += "`n" + $line
            if ($CurrentEntry.Message) {
                $CurrentEntry.Message += "`n" + $line
            }
            #Write-Host "Appended continuation of log to previous log entry $($LineNumber)."
            Write-Host "$($LineNumber): $line"
        }
        elseif ((($i + 1) -eq $RawLogEntries.Count) -and $CurrentEntry) {
            $ParsedLogEntries += $CurrentEntry
        }
        else {
            Write-Host "WARNING: Line did not match log line regex, and does not seem to be a continuation of a previous log."
            Write-Host "$($line)"
        }
    }

    Write-Host "Finished parsing $($ParsedLogEntries.Count) logs from $($Path)"

    if ($SinceDateTime) {
        $ParsedLogEntries = $ParsedLogEntries | Where-Object { $_.Timestamp -ge $SinceDateTime }
    }

    if ($ReturnObject) {
        return $ParsedLogEntries
    }
    else {
        $FileName = ".\$($LogFileName)_logs_parsed_$((Get-Date -Format 'yyyy-MM-dd_HH-mm').ToString()).csv"
        $ParsedLogEntries | Export-Csv -Path $FileName
        Write-Host "Exported parsed logs to CSV: $($FileName)"
    }
}

Export-ModuleMember -Function Test-SSLDecryption
Export-ModuleMember -Function Test-HarFileForDecryptedUrls
Export-ModuleMember -Function Get-HarFileUniqueDomains
Export-ModuleMember -Function Export-PanLogFileToCsv
