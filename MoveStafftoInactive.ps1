# Check if the ActiveDirectory module is installed
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


# Import the Active Directory module
Import-Module ActiveDirectory

# Set the OU to search for disabled user accounts
$searchOU = "OU=Staff,OU=Staff,OU=Accounts,DC=curric,DC=stfx"

# Set the year
$year = "2023"

# Set the OUs to move disabled user accounts to
$moveOUs = @{
    "Term 1" = "OU=Term 1,OU=$year,OU=InactiveStaff,OU=Inactive,OU=Accounts,DC=curric,DC=stfx"
    "Term 2" = "OU=Term 2,OU=$year,OU=InactiveStaff,OU=Inactive,OU=Accounts,DC=curric,DC=stfx"
    "Term 3" = "OU=Term 3,OU=$year,OU=InactiveStaff,OU=Inactive,OU=Accounts,DC=curric,DC=stfx"
    "Term 4" = "OU=Term 4,OU=$year,OU=InactiveStaff,OU=Inactive,OU=Accounts,DC=curric,DC=stfx"
}



# Prompt the host for the term
$term = Read-Host -Prompt 'What term is it? (Term 1/Term 2/Term 3/Term 4)'


# Check if the term is valid
if ($moveOUs.ContainsKey($term)) {
    # Get the OU to move disabled user accounts to
    $moveOU = $moveOUs[$term]

    # Search for disabled user accounts in the specified OU that do not have the name "Template"
    $disabledUsers = Get-ADUser -Filter {Enabled -eq $false -and Name -notlike "*Template*"} -SearchBase $searchOU

    # Display the number of disabled user accounts that will be moved
    Write-Host "$($disabledUsers.Count) disabled user account(s) will be moved to '$moveOU'"

    # Display the disabled user accounts that will be moved
    Write-Host "The following disabled user accounts will be moved to '$moveOU':"
    $disabledUsers | Format-Table -Property SamAccountName

    # Prompt for confirmation
    $confirmation = Read-Host -Prompt 'Do you want to move these disabled user accounts? (y/n)'

    if ($confirmation -eq 'y') {
        # Move disabled user accounts to the specified OU
        foreach ($disabledUser in $disabledUsers) {
            try {
                # Move the disabled user account
                Move-ADObject -Identity $disabledUser.DistinguishedName -TargetPath $moveOU

                # Display a confirmation message
                Write-Host "Disabled user account '$($disabledUser.SamAccountName)' successfully moved to '$moveOU'"
            } catch {
                # Display an error message
                Write-Error "Failed to move disabled user account '$($disabledUser.SamAccountName)' to '$moveOU': $_"
            }
        }
    } else {
        # User did not confirm movement of disabled user accounts
        Write-Host "Movement of disabled user accounts cancelled"
    }
} else {
    # Display an error message
    Write-Error "Invalid term: '$term'"
}
