<#
.SYNOPSIS
This script automates the user account creation process, ensuring a streamlined and error-resistant approach.
.DESCRIPTION
The script checks for the ActiveDirectory module and installs it if necessary. It then proceeds to gather staff information, generate a unique username, and create the user account with specified group memberships.
#>

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

<#
.SYNOPSIS
Define group variables for different teaching and non-teaching staff categories at various locations.
.DESCRIPTION
These group memberships ensure that users have the necessary access rights and permissions based on their roles and responsibilities.
#>

$BeaconsfieldTeachingGroups = @("MFA_Enable", "BEA-teachers", "Lanschool Teachers", "Teaching Staff Beaconsfield", "Teaching Staff Beaconsfield Role", "Zscaler-TeachingStaff", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default", "ViviPresenters")

$BerwickTeachingGroups = @("MFA_Enable", "Lanschool Teachers", "Teaching Staff Berwick", "Teaching Staff Berwick Role", "Zscaler-TeachingStaff", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default", "ViviPresenters")

$OfficerTeachingGroups = @("MFA_Enable", "Lanschool Teachers", "Teaching Staff Officer", "Teaching Staff Officer Role", "Zscaler-TeachingStaff", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default", "ViviPresenters")

$BeaconsfieldNonTeachingGroups = @("MFA_Enable", "Education Support Staff Beaconsfield", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default", "ViviPresenters")

$BerwickNonTeachingGroups = @("MFA_Enable", "Education Support Staff Berwick", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default", "ViviPresenters")

$OfficerNonTeachingGroups = @("MFA_Enable", "Education Support Staff Officer", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default", "ViviPresenters")

<#
.SYNOPSIS
Generate a random password for the new user account.
.DESCRIPTION
The password includes a mix of uppercase letters, lowercase letters, and a random number to ensure security.
#>

$alphabet = "abcdefghijklmnopqrstuvwxyz"
$capitalLetter = Get-Random -InputObject ([char[]] "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
$randomLetters = -join (Get-Random -InputObject ([char[]] $alphabet) -Count 6)
$randomNumber = Get-Random -Minimum 0 -Maximum 10
$password = "$capitalLetter$randomLetters$randomNumber"

<#
.SYNOPSIS
Gather staff information, including first and last names.
.DESCRIPTION
Prompt the user to input their first and last names, and use this information to generate a unique username for the new account.
#>

do {
    $firstname = Read-Host -Prompt 'Input first name'
    if ($firstname[-1] -eq ' ') {
        $firstname = $firstname -replace ' $', ''
    }
    $firstname = $firstname.Substring(0,1).ToUpper()+$firstname.Substring(1).ToLower()

    do {
        $lastname = Read-Host -Prompt 'Input last name'
        if ($lastname[-1] -eq ' ') {
            $lastname = $lastname -replace ' $', ''
        }

        if ($lastname.Length -gt 18) {
            Write-Host "Last name cannot be more than 18 characters. Please try again."
        }
    } while ($lastname.Length -gt 18)

    $lastname = $lastname.Substring(0,1).ToUpper()+$lastname.Substring(1).ToLower()

} while ($firstname.Length -eq 0 -or $lastname.Length -eq 0)

Write-Host "First name: $firstname, Last name: $lastname"



# Generate username based on first initial and last name
$username = "$($firstname.SubString(0, 1))$lastname"
$username = $username -replace ' ','' -replace "'",''
$username = $username.ToLower()

# Check if the username is available and make it unique if necessary
Write-Verbose -Message "Checking if [$($username)] is available"
while ($true) {
    $user = Get-ADUser -Filter {SamAccountName -eq $username} -ErrorAction SilentlyContinue
    if ($user) {
        Write-Host "The username '$username' already exists. Trying next letter" -ForegroundColor Red
        $username = "$($firstname.SubString(0, 2))$lastname"
        $username = $username -replace ' ',''
        Write-Host "Trying '$username'" -ForegroundColor Green
    } else {
        Write-Host "The username '$username' is unique and available for use." -ForegroundColor Green
        break
    }
}

<#
.SYNOPSIS
Check if alternative username options are needed, and prompt the user for manual input if necessary.
.DESCRIPTION
If the initially generated username is not unique, the script prompts the user to manually input a username until a unique one is found.
#>

while ($true) {
    $user = Get-ADUser -Filter {SamAccountName -eq $username} -ErrorAction SilentlyContinue
    if ($user) {
        Write-Host "'$username' is not available either. Please try manually inputting a username" -ForegroundColor Red
        $username = Read-Host -Prompt 'Input new username'
    } else {
        Write-Host "'$username' is unique and available for use." -ForegroundColor Green
        break
    }
}

<# Section 2: RFID Input #>
Write-Host "Section 2: RFID Input" -ForegroundColor Cyan
$RFID = Read-Host -Prompt 'Input RFID (Papercut #) (leave blank if not available)'

# Search for users with the same value for otherPager or otherFacsimileTelephoneNumber attributes
if ([string]::IsNullOrWhiteSpace($RFID)) {
    Write-Host "Skipping RFID input" -ForegroundColor Yellow
} else {
    $usersWithSameOtherPagerOrFax = Get-ADUser -Filter {otherPager -eq $RFID -or otherFacsimileTelephoneNumber -eq $RFID} -Properties otherPager, otherFacsimileTelephoneNumber
}

if ($usersWithSameOtherPagerOrFax) {
    # Display a warning message
    Write-Warning "Warning: The following users already have the value '$RFID' assigned to their otherPager or otherFacsimileTelephoneNumber attributes:"
    $usersWithSameOtherPagerOrFax | Format-Table -Property SamAccountName, otherPager, otherFacsimileTelephoneNumber

    # Prompt if host wants to clear otherPager and otherFacsimileTelephoneNumber attributes of other users
    $clearOtherUsers = Read-Host -Prompt 'Do you want to clear the otherPager and otherFacsimileTelephoneNumber attributes of these users? (y/n)'

    if ($clearOtherUsers -eq 'y') {
        foreach ($userWithSameOtherPagerOrFax in $usersWithSameOtherPagerOrFax) {
            try {
                # Clear otherPager and otherFacsimileTelephoneNumber attributes of other users
                Set-ADUser -Identity $userWithSameOtherPagerOrFax.SamAccountName -Clear otherPager, otherFacsimileTelephoneNumber

                # Display a confirmation message
                Write-Host "Success: otherPager and otherFacsimileTelephoneNumber attributes for user '$($userWithSameOtherPagerOrFax.SamAccountName)' cleared" -ForegroundColor Green
            } catch {
                # Display an error message
                Write-Error "Error: Failed to clear otherPager and otherFacsimileTelephoneNumber attributes for user '$($userWithSameOtherPagerOrFax.SamAccountName)': $_" -ForegroundColor Red
            }
        }
    }
} else {
    # No users found with the same value for otherPager or otherFacsimileTelephoneNumber attributes
    Write-Host "No users found with the value '$RFID' assigned to their otherPager or otherFacsimileTelephoneNumber attributes" -ForegroundColor Green
}

# <# Section 3: Campus Input #>
Write-Host "`nSection 3: Campus Input" -ForegroundColor Cyan
# Array of valid entries for PO box
$validPOBoxes = @('BEA', 'BEACONSFIELD', 'BER', 'BERWICK', 'OFF', 'OFFICER') 

# Loop until user inputs a correct PO box
while ($true) {
    $InitPOBox = Read-Host -Prompt 'Input campus (BEA / BER / OFF)'
    $POBox = $InitPOBox.ToUpper()
    if ($validPOBoxes -contains $POBox){
        break
    } else { 
        Write-Host "Invalid campus entered. Please try again" -ForegroundColor Red
    }
}

# Map campus to full name
$CampusMapping = @{
    'BEA' = 'Beaconsfield'
    'BER' = 'Berwick'
    'OFF' = 'Officer'
}

$Campus = $CampusMapping[$POBox]

Write-Host "Success: The given campus is $Campus" -ForegroundColor Green

# <# Section 4: User Role Input #>
Write-Host "`nSection 4: User Role Input" -ForegroundColor Cyan

# Initialize variable
$teachingflag = ""

# Loop until valid input is received
while ($teachingflag -ne "T" -and $teachingflag -ne "N") {
    $teachingflag = Read-Host -Prompt 'Teaching (T) or Non-teaching (N)?'
    $teachingflag = $teachingflag.ToUpper()

    if ($teachingflag -eq "T" -or $teachingflag -eq "N") {
        Write-Host "Success: The given Role is $teachingflag" -ForegroundColor Green
    } else {
        Write-Host "Invalid input. Please enter either 'T' for Teaching or 'N' for Non-teaching." -ForegroundColor Red
    }
}


# Correct user input if necessary
$teachingflag = $teachingflag.ToUpper()

if ($teachingflag -eq 'T') {
    # Prompt the user for the position/title
    $Title = Read-Host -Prompt "Input position/title - (leave blank if 'Classroom Teacher)"
    if ([string]::IsNullOrEmpty($Title)) {
        $Title = 'Classroom Teacher'
    }
    $Department = 'TEACH'
    Write-Host "Success: The given Title is $Title" -ForegroundColor Green

    # Prompt the user for the predecessor username
    $Predecessor = Read-Host -Prompt 'Input exact username to copy AD group membership. LEAVE EMPTY if N/A'

    # Check if the user entered a value for Predecessor
    if ($Predecessor -ne "") {
        # Set a flag to indicate if a valid username has been entered
        $validUsername = $false

        # Loop until a valid username is entered or the user chooses not to try again
        while (!$validUsername) {
            # Search Active Directory for the specified username
            $user = Get-ADUser -Filter {SamAccountName -eq $Predecessor} -ErrorAction SilentlyContinue

            # Check if the user was found
            if ($user) {
                # The user was found
                Write-Host "Success: The user $($user.Name) was found in Active Directory." -ForegroundColor Green

                # Prompt the user to confirm if this is the correct account
                $confirm = Read-Host -Prompt "Is this the correct account? (y/n)"
                if ($confirm -eq "y") {
                    # The user confirmed that this is the correct account
                    Write-Host "Success: The user confirmed that this is the correct account." -ForegroundColor Green
                    $validUsername = $true
                } else {
                    # The user did not confirm that this is the correct account
                    Write-Host "Info: The user did not confirm that this is the correct account." -ForegroundColor Yellow

                    # Prompt the user to try again
                    $retry = Read-Host -Prompt "Do you want to try again? (y/n)"
                    if ($retry -eq "y") {
                        # The user wants to try again

                        # Prompt the user to enter a new username
                        $Predecessor = Read-Host -Prompt "Enter a new username to try again"
                        if ($Predecessor -ne "") {
                            # The user entered a new username
                            Write-Host "Info: The user entered a new username: $Predecessor" -ForegroundColor Yellow
                        } else {
                            # The user did not enter a new username
                            Write-Host "Info: The user did not enter a new username." -ForegroundColor Yellow
                        }
                    } else {
                        # The user does not want to try again
                        Write-Host "Info: The user does not want to try again." -ForegroundColor Yellow
                        break
                    }
                }
            } else {
                # The user was not found
                Write-Host "Error: The user $Predecessor was not found in Active Directory." -ForegroundColor Red

                # Prompt the user to try again
                $retry = Read-Host -Prompt "Do you want to try again? (y/n)"
                if ($retry -eq "y") {
                    # The user wants to try again

                    # Prompt the user to enter a new username
                    $Predecessor = Read-Host -Prompt "Enter a new username to try again"
                    if ($Predecessor -ne "") {
                        # The user entered a new username
                        Write-Host "Info: The user entered a new username: $Predecessor" -ForegroundColor Yellow
                    } else {
                        # The user did not enter a new username
                        Write-Host "Info: The user did not enter a new username." -ForegroundColor Yellow
                    }
                } else {
                    # The user does not want to try again
                    Write-Host "Info: The user does not want to try again." -ForegroundColor Yellow
                    break
                }
            }
        }
    }
} elseif ($teachingflag -eq 'N') {
    # <# Section 5: Non-Teaching User Input #>
    Write-Host "`nSection 5: Non-Teaching User Input" -ForegroundColor Cyan
    # Prompt the user for the title
    $Title = Read-Host -Prompt "Input position/title (leave blank if not available)"

    if ([string]::IsNullOrEmpty($Title)) {
        $Title = ''
    }

    $validInput = $false
    while (-not $validInput) {
        # Prompt the user to select an appropriate department
        Write-Host "Select the appropriate department:"
        Write-Host "1. ADMIN"
        Write-Host "2. FIN"
        Write-Host "3. ICT"
        Write-Host "4. CANTEEN"
        Write-Host "5. EXEC"
        Write-Host "6. HR"
        Write-Host "7. LRC"
        Write-Host "8. LSO"
        Write-Host "9. MARKETING"
        Write-Host "10. WELB"
        Write-Host "11. WELF"
        Write-Host "12. UNIF"
        Write-Host "13. COMP"
        Write-Host "14. Other"

        $departmentInput = Read-Host -Prompt "Enter the number corresponding to the department"

        $parsedInt = 0
        if ([int]::TryParse($departmentInput, [ref]$parsedInt) -and $parsedInt -ge 1 -and $parsedInt -le 14) {
            $validInput = $true
        } else {
            Write-Host "Invalid input. Please enter a number between 1 and 14." -ForegroundColor Red
        }
    }

    # Set the appropriate department based on the user's selection
    switch ($departmentInput) {
        1 { $Department = "ADMIN" }
        2 { $Department = "FIN" }
        3 { $Department = "ICT" }
        4 { $Department = "CANTEEN" }
        5 { $Department = "EXEC" }
        6 { $Department = "HR" }
        7 { $Department = "LRC" }
        8 { $Department = "LSO" }
        9 { $Department = "MARKETING" }
        10 { $Department = "WELB" }
        11 { $Department = "WELF" }
        12 { $Department = "UNIF" }
        13 { $Department = "COMP" }
        14 { $Department = "" }  # Set the department to blank for "Other" selection
        default { $Department = $null }
    }

    Write-Host "Success: The selected Department is $Department" -ForegroundColor Green
}

# <# Section 6: Creating New User Account #>
Write-Host "`nSection 6: Creating New User Account" -ForegroundColor Cyan

try {
    # Define parameters for the new user
    $NewUserParams = @{
        'UserPrincipalName'    = "$username@sfx.vic.edu.au".ToLower()
        'Name'                 = "$firstname $lastname"
        'GivenName'            = $firstname
        'Surname'              = $lastname
        'EmailAddress'         = "$username@sfx.vic.edu.au".ToLower()
        'SamAccountName'       = "$username".ToLower()
        'AccountPassword'      = (ConvertTo-SecureString "$password" -AsPlainText -Force)
        'Enabled'              = $true
        'Path'                 = "OU=Staff,OU=Staff,OU=Accounts,DC=curric,DC=stfx"
        'ChangePasswordAtLogon'= $true
        'DisplayName'          = "$FirstName $LastName"
        'OtherAttributes'      = @{ProxyAddresses="SMTP:$username@sfx.vic.edu.au"}
        'POBox'                = "$POBox"
        'City'                 = "$Campus"
        'Title'                = "$Title"
        'Company'              = 'E4031'
        'Department'           = "$Department"
    }

    # Create the new user account
    New-ADUser @NewUserParams
    Write-Host "Success: The new user account $($username) has been created." -ForegroundColor Green
}
catch {
    Write-Host "Error: Failed to create the new user account. Either restart the script or manually create the user. Details: $($_.Exception.Message)" -ForegroundColor Red
    # You can log the error to a file or take other appropriate actions.
    return  # End the script without exiting
}


# <# Section 7: Password Modification and Additional Attributes #>
Write-Host "`nSection 7: Password Modification and Additional Attributes" -ForegroundColor Cyan

# Add a pause for 5 seconds (adjust as needed)
Start-Sleep -Seconds 5

# Initialize retry parameters
$retryCount = 0
$maxRetries = 3
$foundUser = $false

# Retry loop to wait for the user to be found in Active Directory
while (-not $foundUser -and $retryCount -lt $maxRetries) {
    $user = Get-ADUser -Filter "SamAccountName -eq '$username'"
    if ($user) {
        $foundUser = $true
    }
    else {
        $retryCount++
        Start-Sleep -Seconds 5
    }
}

if ($foundUser) {
    # User found, proceeding with password modification
    Set-ADAccountPassword -Identity $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$Password" -Force)
    Write-Host "Success: Password for user $($username) has been modified." -ForegroundColor Green
}
else {
    Write-Host "Error: User $username not found in Active Directory. Password modification skipped." -ForegroundColor Red
}

# Check if the user entered a value for RFID
if ($RFID -ne "") {
    # Set the otherpager attribute to the value of $RFID
    Set-ADUser -Identity $username -Replace @{otherpager = $RFID}
    Write-Host "RFID information added for user $($username)." -ForegroundColor Green
}

# Store the username in clipboard for easy pasting
$Paste = $username
Write-Host "The username $($username) is now stored in the clipboard for easy pasting." -ForegroundColor Yellow


# <# Section 8: Group Memberships and Predecessor Handling #>
Write-Host "`nSection 8: Group Memberships and Predecessor Handling" -ForegroundColor Cyan

# Determine the groups to check based on teaching flag and PO Box
$groupsToCheck = switch ($teachingflag) {
    'T' {
        switch ($POBox) {
            'BEA' { $BeaconsfieldTeachingGroups }
            'BER' { $BerwickTeachingGroups }
            'OFF' { $OfficerTeachingGroups }
        }
    }
    'N' {
        switch ($POBox) {
            'BEA' { $BeaconsfieldNonTeachingGroups }
            'BER' { $BerwickNonTeachingGroups }
            'OFF' { $OfficerNonTeachingGroups }
        }
    }
}

# Get the group memberships of the newly created user
$userGroups = Get-ADPrincipalGroupMembership -Identity $username -Server "bea-p-dc1" | Select-Object -ExpandProperty Name

# Check and update group memberships for the new user
foreach ($group in $groupsToCheck) {
    if ($userGroups -contains $group) {
        Write-Host "Info: User $username is already a member of group $group" -ForegroundColor Yellow
    } else {
        Write-Host "Info: Adding user $username to group $group" -ForegroundColor Cyan
        try {
            Add-ADGroupMember -Identity $group -Members $username -ErrorAction Stop
            Write-Host "Success: User $username added to group $group" -ForegroundColor Green
        } catch {
            Write-Host "Error: Failed to add user $username to group $group. Details: $_" -ForegroundColor Red
        }
    }
}

# Check if a predecessor was specified
if (![string]::IsNullOrEmpty($Predecessor)) {
    # Search Active Directory for the specified predecessor username
    $predecessorUser = Get-ADUser -Filter {SamAccountName -eq $Predecessor} -ErrorAction SilentlyContinue

    # Check if the predecessor user was found
    if ($predecessorUser) {
        # The predecessor user was found
        Write-Host "Info: Predecessor user $($predecessorUser.Name) found in Active Directory." -ForegroundColor Cyan

        # Get the group memberships of the predecessor user
        $predecessorGroups = Get-ADUser $predecessorUser | Get-ADPrincipalGroupMembership | Select-Object -ExpandProperty Name

        # Loop through the groups and add the new user
        foreach ($group in $predecessorGroups) {
            Add-ADGroupMember -Identity $group -Members $Paste
            Write-Host "Success: Added $Paste to group: $group" -ForegroundColor Green
        }
    } else {
        # The predecessor user was not found
        Write-Host "Error: The user $Predecessor was not found in Active Directory." -ForegroundColor Red
    }
}

# <# Section 9: Additional Group and Title Handling #>
Write-Host "`nSection 9: Additional Group and Title Handling" -ForegroundColor Cyan

# Provide option to add User to groups based on Department and update Title if Blank if predecessor not selected
if ([string]::IsNullOrEmpty($Predecessor) -and $Department -ne "Other" -and ![string]::IsNullOrEmpty($Department)) {
    Write-Host "Info: Searching for recommended groups based on user selections" -ForegroundColor Green

    if ($teachingflag -eq 'N') {
        # Search Active Directory for users based on department and PO Box
        $foundUsers = Get-ADUser -Filter {
            Department -eq $Department -and
            POBox -eq $POBox
        } -Properties Name, Title, City

        # Display the list of found users with their names and titles
        if ($foundUsers) {
            Write-Host "Info: Users found in Active Directory:"
            $userIndex = 1
            foreach ($user in $foundUsers) {
                Write-Host "[$userIndex] $($user.Name) - $($user.Title) - $($user.City)"
                $userIndex++
            }

            $selectedUser = $null

            # Prompt the user to select a user or skip
while ($selectedUser -eq $null) {
    $selectedUserIndex = Read-Host -Prompt "Enter the number corresponding to the user you want to add, 'L' to lessen the search, or 'S' to skip"

    if ($selectedUserIndex -eq 'S' -or $selectedUserIndex -eq 's') {
        Write-Host "Info: Skipping adding the new user to groups." -ForegroundColor Yellow
        break
    } elseif ($selectedUserIndex -eq 'L' -or $selectedUserIndex -eq 'l') {
        Write-Host "Info: Lessening the search criteria to only Department." -ForegroundColor Yellow

        # Search Active Directory for users based on department only
        $foundUsers = Get-ADUser -Filter {
            Department -eq $Department
        } -Properties Name, Title, City

        # Display the list of found users with their names and titles
        if ($foundUsers) {
            Write-Host "Info: Users found in Active Directory:"
            $userIndex = 1
            foreach ($user in $foundUsers) {
                Write-Host "[$userIndex] $($user.Name) - $($user.Title) - $($user.City)"
                $userIndex++
            }
        } else {
            Write-Host "Info: No users found in Active Directory based on the specified criteria." -ForegroundColor Yellow
        }
    } else {
        $selectedUserIndex = [int]$selectedUserIndex  # Convert the input to an integer

        if ($selectedUserIndex -ge 1 -and $selectedUserIndex -le $foundUsers.Count) {
            $selectedUser = $foundUsers[$selectedUserIndex - 1]
            Write-Host "Info: Selected user: $($selectedUser.Name) - $($selectedUser.Title)" -ForegroundColor Cyan
        } else {
            Write-Host "Error: Invalid user selection. Please try again." -ForegroundColor Red
        }
    }

    }


            if ($selectedUser -ne $null) {
                # Update the new user's title if blank
                if ([string]::IsNullOrEmpty($Title)) {
                    $Title = $selectedUser.Title
                    Write-Host "Success: New user's title updated from selected user: $($Title)" -ForegroundColor Green

                    # Update the Title field in Active Directory
                    try {
                        Set-ADUser -Identity $username -Title $Title
                        Write-Host "Success: User $($username)'s Title field updated in Active Directory: $Title." -ForegroundColor Green
                    } catch {
                        Write-Host "Error: Failed to update the Title field for user $($username)." -ForegroundColor Red
                    }
                }

                # Prompt the user to confirm adding the new user to the groups discovered by the selected user
$confirmAddToGroups = Read-Host -Prompt "Do you want to add the new user to the groups discovered by $($selectedUser.Name)? (y/n)"

if ($confirmAddToGroups -eq "y") {
    # Get the group memberships of the selected user
    $selectedUserGroups = Get-ADPrincipalGroupMembership -Identity $selectedUser | Select-Object -ExpandProperty Name

    # Initialize an array to store the groups where adding the user failed
$failedGroups = @()

 # Add the new user to the discovered groups
foreach ($group in $selectedUserGroups) {
    $retryCount = 0
    while ($retryCount -lt 3) {
        try {
            Add-ADGroupMember -Identity $group -Members $Paste -Verbose
            Write-Host "Success: New user added to group: $($group)" -ForegroundColor Green
            break
        } catch {
            Write-Host "Error: Failed to add new user to group: $($group). Attempt $($retryCount+1)" -ForegroundColor Red
            $retryCount++
            if ($retryCount -eq 3) {
                # If all attempts fail, add the group to the failedGroups array
                $failedGroups += $group
            }
            if ($retryCount -lt 3) {
                Write-Host "Retrying in 5 seconds..."
                Start-Sleep -Seconds 5
            }
        }
    }

    }
} else {
    Write-Host "Info: Adding new user to groups skipped." -ForegroundColor Yellow
}

            } else {
                Write-Host "Error: Invalid user selection." -ForegroundColor Red
            }
        } else {
            Write-Host "Info: No users found in Active Directory based on the specified criteria." -ForegroundColor Yellow
        }
    }
}

# End of Section 9

# <# Section 10: Microsoft Teams Integration and Script Finalization #>
Write-Host "`nSection 10: Microsoft Teams Integration and Script Finalization" -ForegroundColor Cyan

# Construct the user's email
$userEmail = "$username@sfx.vic.edu.au"

# Define the team group IDs based on the value of $POBox
$teamGroupIDs = @{
    'BEA' = 'd836e50f-7592-417c-94f7-b7ea25d6565c'
    'OFF' = '09aa45a0-5a49-4a61-bb35-96cdbba070af'
    'BER' = '653dac8e-56ab-4779-909b-a6b065922b75'
}

# Prompt the user before adding them to the team
$confirmation = Read-Host "Do you want to add $username to the $POBox Team? (Y/N)"

if ($confirmation -eq "Y") {
    # Check if the MicrosoftTeams module is installed, if not, install it
    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force -Repository PSGallery
    }

    $connectedToTeams = $false

    do {
        # Prompt for password
        $teamsPassword = Read-Host -Prompt "Enter your Teams admin password" -AsSecureString
        $teamsCredential = New-Object System.Management.Automation.PSCredential("teamsadmin@sfx.vic.edu.au", $teamsPassword)

        try {
            Connect-MicrosoftTeams -Credential $teamsCredential -ErrorAction Stop
            $connectedToTeams = $true
            Write-Host "Success: Successfully connected to Microsoft Teams." -ForegroundColor Green
        } catch {
            Write-Error "Error: Failed to connect to Microsoft Teams. Please check your credentials and try again."
        }
    } while (-not $connectedToTeams)

    $retry = $true

    while ($retry) {
        # Calculate the delay until the next 10th minute
        $currentMinute = (Get-Date).Minute
        $delayMinutes = ((10 - ($currentMinute % 10)) % 10) * 60 - (Get-Date).Second

        # Ensure the delay is positive
        if ($delayMinutes -lt 0) {
            $delayMinutes += 600  # Add 10 minutes to the delay
        }

        # Calculate the target time to add the user
        $targetTime = (Get-Date).AddSeconds($delayMinutes).ToString("HH:mm:ss")

        # Display the target time to the user
        Write-Host "Info: User will be added to the team at $targetTime." -ForegroundColor Yellow

        # Wait until the target time
        Write-Host "Info: Waiting until $targetTime to add the user..." -ForegroundColor Yellow
        Start-Sleep -Seconds $delayMinutes

        $retryCount = 0
        $maxRetries = 3
        $userAdded = $false

        while (-not $userAdded -and $retryCount -lt $maxRetries) {
            # Add the user to the team
            $teamGroupId = $teamGroupIDs[$POBox]
            if ($teamGroupId) {
                try {
                    Add-TeamUser -GroupId $teamGroupId -User $userEmail -ErrorAction Stop
                    $userAdded = $true
                    Write-Host "Success: User added to the team successfully." -ForegroundColor Green
                } catch {
                    $retryCount++
                    Write-Error "Error: Failed to add user to the team. Retrying... (Attempt $retryCount)"

                    # Prompt the user for a yes/no response
                    $retry = Read-Host "Do you want to try adding $username to the $POBox Team again? (Y/N)" -eq "Y"

                    # If user responds with anything other than "Y", set $retry to false to continue with the rest of the script
                    if ($retry -ne "Y") {
                        $retry = $false
                    }
                    
                    Start-Sleep -Seconds 5
                }
            } else {
                Write-Error "Error: Invalid POBox value. No team group ID found."
                
                # Prompt the user for a yes/no response
                $retry = Read-Host "Do you want to try adding $username to the $POBox Team again? (Y/N)" -eq "Y"

                # If user responds with anything other than "Y", set $retry to false to continue with the rest of the script
                if ($retry -ne "Y") {
                    $retry = $false
                }
            }
        }

        if ($userAdded) {
            $retry = $false
        } elseif ($retryCount -ge $maxRetries) {
            Write-Error "Error: Failed to add user to the team after $maxRetries attempts."
            
            # Prompt the user for a yes/no response
            $retry = Read-Host "Do you want to try adding $username to the $POBox Team again? (Y/N)" -eq "Y"

            # If user responds with anything other than "Y", set $retry to false to continue with the rest of the script
            if ($retry -ne "Y") {
                $retry = $false
            }
        }
    }
}

# Continue with the rest of the script
Write-Output "Info: Rest of the script execution continues..."



# <# Section 11: Script Conclusion and User Feedback #>
Write-Host "`nSection 11: Script Conclusion and User Feedback" -ForegroundColor Cyan

# Search for the user that was created
$searchResult = Get-ADUser -Identity $username

# Check if the search result is not null
if ($searchResult -ne $null) {
    # The user was found
    Write-Output "Success: The user $($searchResult.Name) was found in Active Directory."
    Write-Host "Success: User $($username) has been created" -ForegroundColor Green
    #Write-Host "`nRemember to continue with the following, where applicable:`n" -ForegroundColor Yellow
    #Write-Host "`t- Amend Simon Account`n`t- Create Quickpin`n`t- Shared inboxes" -ForegroundColor Cyan
    Write-Host "`nTemp Password: $Password" -ForegroundColor Magenta

    # If there are any failed groups, display them
    if ($failedGroups.Count -gt 0) {
        Write-Host "`nFailed to add the user to the following groups: Please add them if missing" -ForegroundColor Red
        foreach ($group in $failedGroups) {
            Write-Host "`t$group" -ForegroundColor Red
        }
    }
}

Read-Host -Prompt "Info: Press Enter to exit"

# Prompt the user to restart the script
$restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'

if ($restart -eq 'y') {
    # Restart the script
    & $PSCommandPath
} else {
    # Keep the PowerShell window open
    pause
}

# End of Script
