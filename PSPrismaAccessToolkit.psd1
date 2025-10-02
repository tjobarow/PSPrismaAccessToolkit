@{
    # Module identity
    RootModule        = 'PSPrismaAccessToolkit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'd2f9b2e9-4c7a-4a9b-9c23-8b7f6f2c1a3e'

    # Author / company
    Author            = 'Thomas Obarowski'
    CompanyName       = 'N/A'
    Copyright         = '(c) 2025 Thomas Obarowski. MIT License.'

    # Descriptive
    Description       = 'A collection of PowerShell functions for troubleshooting Prisma Access deployments: SSL decryption validation, HAR analysis and GlobalProtect log parsing.'
    ProjectUri        = 'https://github.com/tjobarow/PSPrismaAccessToolkit'
    LicenseUri        = 'https://github.com/tjobarow/PSPrismaAccessToolkit/blob/main/LICENSE'
    ReleaseNotes      = 'Initial release'

    # PowerShell compatibility
    PowerShellVersion = '5.1'


    # Exports (match the Export-ModuleMember in the .psm1)
    FunctionsToExport = @(
        'Test-SSLDecryption'
        'Test-HarFileForDecryptedUrls'
        'Get-HarFileUniqueDomains'
        'Export-PanLogFileToCsv'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    # Files included in module package (helpful for packaging)
    FileList = @(
        'PSPrismaAccessToolkit.psm1',
        'PSPrismaAccessToolkit.psd1',
        'LICENSE',
        'README.md'
    )

    # Dependencies
    RequiredModules   = @()
    RequiredAssemblies = @()

    # Tags and metadata (also duplicated in PrivateData.PSData for tooling)
    Tags = @('Prisma Access','Palo Alto','SSL','Decryption','GlobalProtect','HAR','Automation','Troubleshooting')

    PrivateData = @{
        PSData = @{
            Tags = @('Prisma Access','Palo Alto','SSL','Decryption','GlobalProtect','HAR','Automation','Troubleshooting')
            LicenseUri = 'https://github.com/tjobarow/PSPrismaAccessToolkit/blob/main/LICENSE'
            ProjectUri = 'https://github.com/tjobarow/PSPrismaAccessToolkit'
            ReleaseNotes = 'Initial release - v1.0.0'
        }
    }
}