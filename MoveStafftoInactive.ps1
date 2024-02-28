if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Output "ActiveDirectory module is already installed."
} else {
    # ensure running as admin before installing
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    
        Write-Warning "This script must be run as an administrator to install the ActiveDirectory module. Please restart the script with administrative privileges."
        
        $restart = Read-Host -Prompt 'Do you want to restart the script with administrative privileges? (y/n)'
        if ($restart -eq 'y') {
            
            Start-Process PowerShell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
        }
        return
    }

    # install module
    Install-WindowsFeature -Name RSAT-AD-PowerShell
}


Import-Module ActiveDirectory

# scope
$searchOU = "OU=Staff,OU=Staff,OU=Accounts,DC=curric,DC=stfx"

# year
$year = "2024"

# target OUs to move into
$moveOUs = @{
    "Term 1" = "OU=Term 1,OU=$year,OU=InactiveStaff,OU=Inactive,OU=Accounts,DC=curric,DC=stfx"
    "Term 2" = "OU=Term 2,OU=$year,OU=InactiveStaff,OU=Inactive,OU=Accounts,DC=curric,DC=stfx"
    "Term 3" = "OU=Term 3,OU=$year,OU=InactiveStaff,OU=Inactive,OU=Accounts,DC=curric,DC=stfx"
    "Term 4" = "OU=Term 4,OU=$year,OU=InactiveStaff,OU=Inactive,OU=Accounts,DC=curric,DC=stfx"
}



# gather input
$term = Read-Host -Prompt 'What term is it? (Term 1/Term 2/Term 3/Term 4)'


# validate input before proceeding
if ($moveOUs.ContainsKey($term)) {
    $moveOU = $moveOUs[$term]

    # check for non-template user accounts that are disabled
    $disabledUsers = Get-ADUser -Filter {Enabled -eq $false -and Name -notlike "*Template*"} -SearchBase $searchOU

    # display count and names of users that will be moved
    Write-Host "$($disabledUsers.Count) disabled user account(s) will be moved to '$moveOU'"
    Write-Host "The following disabled user accounts will be moved to '$moveOU':"
    $disabledUsers | Format-Table -Property SamAccountName

    # confirm
    $confirmation = Read-Host -Prompt 'Do you want to move these disabled user accounts? (y/n)'

    if ($confirmation -eq 'y') {
        foreach ($disabledUser in $disabledUsers) {
            try {
                # move
                Move-ADObject -Identity $disabledUser.DistinguishedName -TargetPath $moveOU

                # confirm
                Write-Host "Disabled user account '$($disabledUser.SamAccountName)' successfully moved to '$moveOU'"
            } catch {
                Write-Error "Failed to move disabled user account '$($disabledUser.SamAccountName)' to '$moveOU': $_"
            }
        }
    } else {
        Write-Host "Movement of disabled user accounts cancelled"
    }
} else {
    Write-Error "Invalid term: '$term'"
}
