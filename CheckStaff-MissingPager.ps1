﻿# Check if the ActiveDirectory module is installed
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Output "ActiveDirectory module is already installed."
} else {
    # Check if the script is being run as an administrator
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # Display a warning message
        Write-Warning "This script must be run as an administrator to install the ActiveDirectory module. Please restart the script with administrative privileges."
        # Prompt the user to restart the script with administrative privileges
        $restart = Read-Host -Prompt 'Do you want to restart the script with administrative privileges? (y/n)'
        if ($restart -eq 'y') {
            # Restart the script with administrative privileges
            Start-Process PowerShell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
        }
        # End the script
        return
    }

    # Install the ActiveDirectory module
    Install-WindowsFeature -Name RSAT-AD-PowerShell
}


$OUpath = 'OU=Staff,OU=Staff,OU=Accounts,DC=curric,DC=stfx'
$ExportPath = 'C:\Temp\NoPager\ExportFile.csv'
Get-ADUser -Filter {(otherpager -notlike "*") -and (otherfacsimileTelephoneNumber -notlike "*") -and (Enabled -eq $true)} -SearchBase $OUpath -Properties otherpager, otherfacsimileTelephoneNumber | Select-Object Name, otherpager, otherfacsimileTelephoneNumber | Export-Csv -Path $ExportPath -NoTypeInformation
