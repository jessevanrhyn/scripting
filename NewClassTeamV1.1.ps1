# Check if the MicrosoftTeams module is installed
if (Get-Module -ListAvailable -Name MicrosoftTeams) {
    Write-Output "MicrosoftTeams module is already installed."
} else {
    # Check if the script is being run as an administrator
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # Display a warning message
        Write-Warning "This script must be run as an administrator to install the MicrosoftTeams module. Please restart the script with administrative privileges."
        # Prompt the user to restart the script with administrative privileges
        $restart = Read-Host -Prompt 'Do you want to restart the script with administrative privileges? (y/n)'
        if ($restart -eq 'y') {
            # Restart the script with administrative privileges
            Start-Process PowerShell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
        }
        # End the script
        return
    }

    # Install the MicrosoftTeams module
    Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force -Repository 'PSGallery'
}

$retry = $true
while ($retry) {
    $username = "teamsadmin@sfx.vic.edu.au"
    $password = Read-Host -Prompt "Enter Teams Admin Password" -AsSecureString
    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password
    try {
        Connect-MicrosoftTeams -Credential $credential
        $retry = $false
    } catch {
        Write-Error "Failed to connect to MicrosoftTeams"
        $response = Read-Host -Prompt 'Do you want to try again? (could not connect) (y/n)'
        if ($response -ne 'y') {
            $retry = $false
            exit
        }
    }
}

$Year = "2024"

# gather inputs
do {
    $TeamName = Read-Host -Prompt 'Input Class Code/Team Name (do not include the year)'
    if ($TeamName -match $year) {
        Write-Warning "Warning: The team name should not contain the value of the year"
        $retry = $true
    } else {
        $retry = $false
    }
} while ($retry)
$DisplayName = $TeamName
$TeamName = $TeamName.replace(' ','')
$MailNickName = $TeamName
$MailNickName = $MailNickname -replace '[^\w]', ''

# create new team
$team = New-Team -MailNickName $Year-$MailNickname -DisplayName $Year-$TeamName -Template EDU_Class

if ($team -ne $null) {
    # prompt for owners
    Import-Module ActiveDirectory -Force

    do {
        $retry = $true
        while ($retry) {
            $Owner = Read-Host -Prompt 'Input Owner Email'
            $user = Get-ADUser -Filter { EmailAddress -eq $Owner }
            if ($user -eq $null) {
                Write-Error "User with email address '$Owner' not found in Active Directory domain"
                $response = Read-Host -Prompt 'Do you want to try again? (User not found) (y/n)'
                if ($response -ne 'y') {
                    $retry = $false
                }
            } else {
                $retry = $false
            }
        }

        # add owner to team
        Add-TeamUser -GroupId $team.GroupId -User $Owner -Role Owner

        # prompt to add another owner
        $addAnother = Read-Host -Prompt 'Do you want to add another owner? (y/n)'
    } while ($addAnother -eq 'y')

    # confirm team creation
    Write-Host "Team '$Year-$TeamName' created successfully!" -ForegroundColor Green
} else {
    Write-Warning "Warning: Team '$Year-$TeamName' was not created"
}

# Prompt the user to restart the script
$restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'

if ($restart -eq 'y') {
    # Restart the script
    & $PSCommandPath
} else {
    # Keep the PowerShell window open
    pause
}
