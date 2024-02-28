# check for module
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Output "ActiveDirectory module is already installed."
} else {
    # admin check
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {        
        Write-Warning "This script must be run as an administrator to install the ActiveDirectory module. Please restart the script with administrative privileges."
        $restart = Read-Host -Prompt 'Do you want to restart the script with administrative privileges? (y/n)'
        if ($restart -eq 'y') {
            # restart
            Start-Process PowerShell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
        }
        # end
        return
    }

    # install module if needed
    Install-WindowsFeature -Name RSAT-AD-PowerShell
}

# group vars to add user into
$BeaconsfieldTeachingGroups = @("MFA_Enable", "BEA-teachers", "Lanschool Teachers", "Teaching Staff Beaconsfield", "Teaching Staff Beaconsfield Role", "Zscaler-TeachingStaff", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default")
$BerwickTeachingGroups = @("MFA_Enable", "Lanschool Teachers", "Teaching Staff Berwick", "Teaching Staff Berwick Role", "Zscaler-TeachingStaff", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default")
$OfficerTeachingGroups = @("MFA_Enable", "Lanschool Teachers", "Teaching Staff Officer", "Teaching Staff Officer Role", "Zscaler-TeachingStaff", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default")

$BeaconsfieldNonTeachingGroups = @("MFA_Enable", "Non-Teaching Staff Beaconsfield", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default")
$BerwickNonTeachingGroups = @("MFA_Enable", "Non-Teaching Staff Berwick", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default")
$OfficerNonTeachingGroups = @("MFA_Enable", "Non-Teaching Staff Officer", "Domain Users", "Fundamentals", "Licensing_CodeTwo_Signatures", "Licensing_Office365_Staff_A5", "Papercut Access", "PolicyConnect User", "PolicyPlus Public RO", "SFX-TP-CallerID-Default", "SFX-TP-Calling-Default", "SFX-TP-CallPark-Default", "SFX-TP-Voicemail-Default", "SFX-TP-VoiceRouting-Default")


# gen random pw
$alphabet = "abcdefghijklmnopqrstuvwxyz"
$capitalLetter = Get-Random -InputObject ([char[]] "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
$randomLetters = -join (Get-Random -InputObject ([char[]] $alphabet) -Count 6)
$randomNumber = Get-Random -Minimum 0 -Maximum 10
$password = "$capitalLetter$randomLetters$randomNumber"

# name inputs
$firstname = Read-Host -Prompt 'Input first name'
$lastname = Read-Host -Prompt 'Input last name'

# create user
$username = "$($firstname.SubString(0, 1))$lastname"
$username = $username -replace ' ','' -replace "'",''
$username = $username.ToLower()

# check username, make unique if needed
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

# Check if letters one and two (e.g. jevanrhyn instead of jvanrhyn) work, then manually prompt user for input
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

# get predecessor username for group inheritance
$Predecessor = Read-Host -Prompt 'Input exact username to copy AD group membership. LEAVE EMPTY if N/A'

# check and validate input
if ($Predecessor -ne "") {
    # flag for looping
    $validUsername = $false

    # loop until valid username found
    while (!$validUsername) {
        $user = Get-ADUser -Filter {SamAccountName -eq $Predecessor} -ErrorAction SilentlyContinue

        # check if the user was found
        if ($user) {
            # was found
            Write-Output "The user $($user.Name) was found in Active Directory."

            # get confirmation
            $confirm = Read-Host -Prompt "Is this the correct account? (y/n)"
            if ($confirm -eq "y") {
                Write-Output "You have confirmed that this is the correct account."
                $validUsername = $true
            } else {
                Write-Output "You have confirmed that this is NOT the correct account."

                # again?
                $retry = Read-Host -Prompt "Do you want to try again? (y/n)"
                if ($retry -eq "y") {

                    $Predecessor = Read-Host -Prompt "Enter a new username to try again"
                    if ($Predecessor -ne "") {
                        Write-Output "The user entered a new username: $Predecessor"
                    } else {
                        Write-Output "The user did not enter a new username."
                    }
                } else {
                    Write-Output "The user does not want to try again."
                    break
                }
            }
        } else {
            # not found
            Write-Output "The user $Predecessor was not found in Active Directory."

            # again?
            $retry = Read-Host -Prompt "Do you want to try again? (y/n)"
            if ($retry -eq "y") {

                $Predecessor = Read-Host -Prompt "Enter a new username to try again"
                if ($Predecessor -ne "") {
                    Write-Output "The user entered a new username: $Predecessor"
                } else {
                    Write-Output "The user did not enter a new username."
                }
            } else {
                Write-Output "The user does not want to try again."
                break
            }
        }
    }
}




$RFID = Read-Host -Prompt 'Input RFID (Papercut #) '

# search for users with the same phone # and RFID #
$usersWithSameOtherPagerOrFax = Get-ADUser -Filter {otherPager -eq $RFID -or otherFacsimileTelephoneNumber -eq $RFID} -Properties otherPager, otherFacsimileTelephoneNumber

if ($usersWithSameOtherPagerOrFax) {
    Write-Warning "The following users already have the value '$RFID' assigned to their otherPager or otherFacsimileTelephoneNumber attributes:"
    $usersWithSameOtherPagerOrFax | Format-Table -Property SamAccountName, otherPager, otherFacsimileTelephoneNumber

    # prompt to clear the other users with those #s
    $clearOtherUsers = Read-Host -Prompt 'Do you want to clear the otherPager and otherFacsimileTelephoneNumber attributes of these users? (y/n)'

    if ($clearOtherUsers -eq 'y') {
        foreach ($userWithSameOtherPagerOrFax in $usersWithSameOtherPagerOrFax) {
            try {
                # clear other users
                Set-ADUser -Identity $userWithSameOtherPagerOrFax.SamAccountName -Clear otherPager, otherFacsimileTelephoneNumber

                # confirm the clear for script runner
                Write-Host "otherPager and otherFacsimileTelephoneNumber attributes for user '$($userWithSameOtherPagerOrFax.SamAccountName)' successfully cleared"
            } catch {
                Write-Error "Failed to clear otherPager and otherFacsimileTelephoneNumber attributes for user '$($userWithSameOtherPagerOrFax.SamAccountName)': $_"
            }
        }
    }
} else {
    # clean, no other users
    Write-Host "No users found with the value '$RFID' assigned to their otherPager or otherFacsimileTelephoneNumber attributes"
}

# array of valid entries for PO box
$validPOBoxes = @('BEA', 'BEACONSFIELD', 'BER', 'BERWICK', 'OFF', 'OFFICER') 

# loop until we get a correct input
while ($true) {
    $InitPOBox = Read-Host -Prompt 'Input campus (BEA / BER / OFF)'
    $POBox = $InitPOBox.ToUpper()
    if ($validPOBoxes -contains $POBox){
        break
    } else { 
        Write-Host "Invalid campus entered. Please try again" -ForegroundColor Red
    }
}

# map POBox to campus field
if($POBox -eq 'BEA' -or $POBox -eq 'BEACONSFIELD'){
    $Campus = 'Beaconsfield'
    $POBox = 'BEA'
} elseif($POBox -eq 'BER' -or $POBox -eq 'BERWICK'){
    $Campus = 'Berwick'
    $POBox = 'BER'
} elseif($POBox -eq 'OFF' -or $POBox -eq 'OFFICER') {
    $Campus = 'Officer'
    $POBox = 'OFF'
}

Write-Host "The given campus is $POBox" -ForegroundColor Green

# configure exact input to match form
$teachingflag = Read-Host -Prompt 'Teaching (T) or Non-teaching (N)?'

# correct user input if necessary
$teachingflag = $teachingflag.ToUpper()

if($teachingflag -eq 'T'){
    $Title = 'Classroom Teacher'
    $Department = 'TEACH'
}

$TitleInput = Read-Host -Prompt "Input position/title - leave blank if 'Classroom Teacher'"

if([bool]$TitleInput -eq $true){
    $Title = $TitleInput
}

# make user
$NewUserParams = @{
    'UserPrincipalName' = "$username@sfx.vic.edu.au".ToLower()
    'Name' = "$firstname $lastname"
    'GivenName' = $firstname
    'Surname' = $lastname
    'EmailAddress' = "$username@sfx.vic.edu.au".ToLower()
    'SamAccountName' = "$username".ToLower()
    'AccountPassword' = (ConvertTo-SecureString "$password" -AsPlainText -Force)
    'Enabled' = $true
    'Path' = "OU=Staff,OU=Staff,OU=Accounts,DC=curric,DC=stfx"
    'ChangePasswordAtLogon' = $true
    'DisplayName' = "$FirstName $LastName"
    'OtherAttributes' = @{ProxyAddresses="SMTP:$username@sfx.vic.edu.au"}
    'POBox' = "$POBox"
    'City' = "$Campus"
    'Title' = "$Title"
    'Company' = 'E4031'
    'Department' = "$Department"
}

New-ADUser @NewUserParams
Write-Host "Creating the new user account $($username)" -ForegroundColor Green

# 5 sec sleep as buffer while account is made
Start-Sleep -Seconds 5

$retryCount = 0
$maxRetries = 3
$foundUser = $false

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

# set user pass
if ($foundUser) {
    Set-ADAccountPassword -Identity $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$Password" -Force)
}
else {
    Write-Host "User $username not found in Active Directory." -ForegroundColor Red
}



# check for RFID input before proceeding
if ($RFID -ne "") {
    # set RFID field
    Set-ADUser -Identity $username -Replace @{otherpager = $RFID}
}

$Paste = $username

if($teachingflag -eq 'T'){
    if($POBox -eq 'BEA'){
        $Copy = 'stemplate1'
    } elseif($POBox -eq 'BER'){
        $Copy = 'stemplate5'
    } elseif($POBox -eq 'OFF') {
        $Copy = 'stemplate6'
    }
} elseif($teachingflag -eq 'N'){
    if($POBox -eq 'BEA'){
        $Copy = 'stemplate2'
    } elseif($POBox -eq 'BER'){
        $Copy = 'stemplate3'
    } elseif($POBox -eq 'OFF') {
        $Copy = 'stemplate4'
    }
} 

if([bool]$Predecessor -eq $true){
    $Copy = $Predecessor
}

# copy group membership to new staff account
$getusergroups = Get-ADUser –Identity $Copy -Properties memberof | Select-Object -ExpandProperty memberof
$getusergroups | Add-ADGroupMember -Members $Paste -Verbose

# catch to check based on the value of $teachingflag and $POBox
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

# get the group memberships of the newly created user
$userGroups = Get-ADPrincipalGroupMembership -Identity $username | Select-Object -ExpandProperty Name

# check if the user is a member of the specified groups
foreach ($group in $groupsToCheck) {
    if ($userGroups -contains $group) {
        Write-Output "User $username is a member of group $group"
    } else {
        Write-Output "User $username is not a member of group $group. Adding user to group."
        try {
            Add-ADGroupMember -Identity $group -Members $username -ErrorAction Stop
            Write-Output "User $username added to group $group"
        } catch {
            Write-Output "Failed to add user $username to group $group. Error: $_"
        }
    }
}

# construct the user's email
$userEmail = "$username@sfx.vic.edu.au"

# define the team group IDs based on the value of $POBox
$teamGroupIDs = @{
    'BEA' = 'd836e50f-7592-417c-94f7-b7ea25d6565c'
    'OFF' = '09aa45a0-5a49-4a61-bb35-96cdbba070af'
    'BER' = '653dac8e-56ab-4779-909b-a6b065922b75'
}

# prompt the user before adding them to the team
$confirmation = Read-Host "Do you want to add $username to the $POBox Team? (Y/N)"

if ($confirmation -eq "Y") {
    # check for teams module
    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force -Repository PSGallery
    }

    $connectedToTeams = $false

    do {
        # get creds
        $teamsCredential = Get-Credential -UserName "[sic]" -Message "Enter your password"

        # Validate the entered username
        if ($teamsCredential.UserName -ne "[sic]") {
            Write-Host "Invalid username. Please enter '[sic]'." -ForegroundColor Red
            Continue
        }

        try {
            Connect-MicrosoftTeams -Credential $teamsCredential -ErrorAction Stop
            $connectedToTeams = $true
            Write-Host "Successfully connected to Microsoft Teams." -ForegroundColor Green
        } catch {
            Write-Error "Failed to connect to Microsoft Teams. Please check your credentials and try again."
        }
    } while (-not $connectedToTeams)

    # calculate the delay until the next 10th minute (when the sync gets run)
    $currentMinute = (Get-Date).Minute
    $delayMinutes = ((10 - ($currentMinute % 10)) % 10) * 60 - (Get-Date).Second

    # determine the target time to add the user
    $targetTime = (Get-Date).AddSeconds($delayMinutes).ToString("HH:mm:ss")

    # display target time to script runner
    Write-Host "User will be added to the team at $targetTime." -ForegroundColor Yellow

    # wait
    Start-Sleep -Seconds $delayMinutes

    $retryCount = 0
    $maxRetries = 3
    $userAdded = $false

    while (-not $userAdded -and $retryCount -lt $maxRetries) {
        # add user
        $teamGroupId = $teamGroupIDs[$POBox]
        if ($teamGroupId) {
            try {
                Add-TeamUser -GroupId $teamGroupId -User $userEmail -ErrorAction Stop
                $userAdded = $true
                Write-Host "User added to the team successfully." -ForegroundColor Green
            } catch {
                $retryCount++
                Write-Error "Failed to add user to the team. Retrying... (Attempt $retryCount)"
                Start-Sleep -Seconds 5
            }
        } else {
            Write-Error "Invalid POBox value. No team group ID found."
            break
        }
    }

    if (-not $userAdded) {
        Write-Error "Failed to add user to the team after $maxRetries attempts."
    }
}

# continue with finals
Write-Output "Rest of the script execution continues..."




# find our fresh uesr
$searchResult = Get-ADUser -Identity $username

# make sure we got a result
if ($searchResult -ne $null) {

    Write-Output "The user $($searchResult.Name) was found in Active Directory."
    Write-Host "User $($username) has been created" -ForegroundColor Green
    Write-Host "`nRemember to continue with the following, where applicable:`n" -ForegroundColor Yellow
    Write-Host "`t- Create Simon Account`n`t- Create Quickpin`n`t- Adobe licensing`n`t- Shared inboxes" -ForegroundColor Cyan
    Write-Host "`nTemp Password: $Password" -ForegroundColor Magenta
}

Read-Host -Prompt "Press Enter to exit"

# check if they want restart
$restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'

if ($restart -eq 'y') {
    # restart
    & $PSCommandPath
} else {
    # keep window open, if not running in SE
    pause
}
