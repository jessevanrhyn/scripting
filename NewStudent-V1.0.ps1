Import-Module ActiveDirectory

    #Change Default P/W
    ###################################
    $Password = 'JumperGreen27'

   

    
    # gather inputs
    
    $firstname = Read-Host -Prompt 'Input first name'

    $lastname = Read-Host -Prompt 'Input last name'

    $StudentID = Read-Host -Prompt 'Input Student ID'

    

   do {
  write-host -nonewline "Enter Year level in Numeric Value: "
  $inputString = read-host
  $yearlevel = $inputString -as [Double]
  $ok = $yearlevel -ne $NULL
  if ( -not $ok ) { write-host "You must enter a numeric value" }
}
until ( $ok )

write-host "You entered: $yearlevel"


   #Change Below Lines each year
   #####################################
    
  if($Yearlevel -eq 7){
   $GradYear = '2028'
   $UN = '28'
} elseif($Yearlevel -eq 8){
   $GradYear = '2027'
   $UN = '27'
} elseif($Yearlevel -eq 9){
   $GradYear = '2026'
   $UN = '26'
} elseif($Yearlevel -eq 10){
   $GradYear = '2025'
   $UN = '25'
} elseif($Yearlevel -eq 11){
   $GradYear = '2024'
   $UN = '24'
} elseif($Yearlevel -eq 12){
   $GradYear = '2023'
   $UN = '23'
} 

# set up format
$validDateFormat = "^(\d{1,2})/(\d{1,2})/(\d{2}|\d{4})$"

# (fruit) loop
do {
    $birthdate = Read-Host "Input birthdate (in DD/MM/YY or DD/MM/YYYY format): "
} until ($birthdate -match $validDateFormat)

# Parse date manually
$day = [int]$matches[1]
$month = [int]$matches[2]
$year = [int]$matches[3]

if ($year -lt 100) {
    # Assume year is in the 2000s if only two digits are provided
    $year += 2000
}

# Validate
try {
    $date = [DateTime]::new($year, $month, $day)
}
catch {
    Write-Host "Invalid date entered."
    return
}

# Convert date format to DDMMYY
$birthdate = $date.ToString("ddMMyy")

# Create $BdayPass
$BdayPass = "SFX-$birthdate"

Write-Host "Password will be: $BdayPass" -ForegroundColor Green



Write-Host GradYear = $GradYear
Write-Host UN = $UN

$username = "$($firstname.SubString(0, 1))$lastname"
    $username = $username.replace(' ','').ToLower()
    $username = "$username$UN"
    $username = $username.replace('-','')
    $username = $username.replace(' ','')
     write-host $username


    
    # Check if an existing user already has the first initial/last name username taken
    Write-Verbose -Message "Checking if [$($username)] is available"

if (@(Get-ADUser -Filter { SamAccountName -eq $username }).Count -eq 1) {
    Write-Warning -Message "User $username already exist and is not available"
    Write-host -message "Gathering Next Initial to use"
    $username = "$($firstname.SubString(0, 2))$lastname"
    $username = $username.replace(' ','').ToLower()
    $username = "$username$UN"
     
    }


elseif (@(Get-ADUser -Filter { SamAccountName -eq $username }).Count -eq 0) {
    Write-host "User $username is available, proceeding with user creation" -ForegroundColor Green
}


Write-Host $username

    $validPOBoxes = @('BEA', 'BEACONSFIELD', 'BER', 'BERWICK', 'OFF', 'OFFICER')

    while ($true){
        $InitPOBox = Read-Host -Prompt 'Input campus (BEA / BER / OFF)'
        $POBox = $InitPOBox.ToUpper()
        if ($validPOBoxes -contains $POBox){
            break
        } else { 
            Write-Host "Invalid campus entered. Please try again" -ForegroundColor Red
            }
        }

    

    if($POBox -eq 'BEA' -or $POBox -eq 'Beaconsfield'){
        $Campus = 'Beaconsfield'
        $POBox = 'BEA'
        

    $NewUserParams = @{
    'UserPrincipalName' = "$username@student.sfx.vic.edu.au".ToLower()
	'Name' = "$firstname $lastname"
	'GivenName' = $firstname
	'Surname' = $lastname
    'EmailAddress' = "$username@student.sfx.vic.edu.au".ToLower()
    'SamAccountName' = "$username".ToLower()
	'AccountPassword' = (ConvertTo-SecureString "$BdayPass" -AsPlainText -Force)
	'Enabled' = $true
    'Description' = "StudentNumber: $StudentID"
	'Path' = "OU=$GradYear,OU=Students,OU=Accounts,DC=curric,DC=stfx"
	'ChangePasswordAtLogon' = $true
    'DisplayName' = "$FirstName $LastName"
    'OtherAttributes' = @{ProxyAddresses="SMTP:$username@student.sfx.vic.edu.au"}
    'POBox' = "$POBox"
    'City' = "$Campus"
    
    
    }
    }

    elseif($POBox -eq 'BER' -or $POBox -eq 'Berwick'){
        $Campus = 'Berwick'
        $POBox = 'BER'
    

        $NewUserParams = @{
    'UserPrincipalName' = "$username@student.sfx.vic.edu.au".ToLower()
	'Name' = "$firstname $lastname"
	'GivenName' = $firstname
	'Surname' = $lastname
    'EmailAddress' = "$username@student.sfx.vic.edu.au".ToLower()
    'SamAccountName' = "$username".ToLower()
	'AccountPassword' = (ConvertTo-SecureString "$BdayPass" -AsPlainText -Force)
	'Enabled' = $true
    'Description' = "StudentNumber: $StudentID"
	'Path' = "OU=$Campus,OU=$GradYear,OU=Students,OU=Accounts,DC=curric,DC=stfx"
	'ChangePasswordAtLogon' = $true
    'DisplayName' = "$FirstName $LastName"
    'OtherAttributes' = @{ProxyAddresses="SMTP:$username@student.sfx.vic.edu.au"}
    'POBox' = "$POBox"
    'City' = "$Campus"
   
    }
    }

    elseif($POBox -eq 'OFF' -or $POBox -eq 'Officer'){
        $Campus = 'Officer'
        $POBox = 'OFF'
        

     $NewUserParams = @{
    'UserPrincipalName' = "$username@student.sfx.vic.edu.au".ToLower()
	'Name' = "$firstname $lastname"
	'GivenName' = $firstname
	'Surname' = $lastname
    'EmailAddress' = "$username@student.sfx.vic.edu.au".ToLower()
    'SamAccountName' = "$username".ToLower()
	'AccountPassword' = (ConvertTo-SecureString "$BdayPass" -AsPlainText -Force)
	'Enabled' = $true
    'Description' = "StudentNumber: $StudentID"
	'Path' = "OU=$Campus,OU=$GradYear,OU=Students,OU=Accounts,DC=curric,DC=stfx"
	'ChangePasswordAtLogon' = $true
    'DisplayName' = "$FirstName $LastName"
    'OtherAttributes' = @{'Pager'=$StudentID;ProxyAddresses="SMTP:$username@student.sfx.vic.edu.au"}
    'POBox' = "$POBox"
    'City' = "$Campus"

    }
    }

    Write-Host "The given campus is $($POBox)" -ForegroundColor Green
    

    New-AdUser @NewUserParams
    Write-Host "Creating the new user account $($username)" -ForegroundColor Green
    
    

       
    $Paste = $username

    #Change Each Year
    ###############################

    if($YearLevel -eq '7'){
        if($POBox -eq 'BER'){
            $Copy = 'a28berstudtemplate'
        }elseif($POBox -eq 'OFF'){
            $Copy = 'a28offstudtemplate'
        }
    }

    elseif($YearLevel -eq '8'){
        if($POBox -eq 'BER'){
            $Copy = 'a27berstudtemplate'
        }elseif($POBox -eq 'OFF'){
            $Copy = 'a27offstudtemplate'
       
        }
    } 

    elseif($YearLevel -eq '9'){
        if($POBox -eq 'BER'){
            $Copy = 'a26berstudtemplate'
        }elseif($POBox -eq 'OFF'){
            $Copy = 'a26offstudtemplate'
       
        }
    } 

     elseif($YearLevel -eq '10'){
            $Copy = 'a25beastudtemplate'
    } 

    elseif($YearLevel -eq '11'){
            $Copy = 'a24beastudtemplate'
    } 

    elseif($YearLevel -eq '12'){
            $Copy = 'a23beastudtemplate'
    } 

    if([bool]$Predecessor -eq $true){
        $Copy = $Predecessor
    }

     
    $getusergroups = Get-ADUser –Identity $Copy -Properties memberof | Select-Object -ExpandProperty memberof

    $getusergroups | Add-ADGroupMember -Members $Paste -verbose

    Set-ADAccountPassword -Identity $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$Bdaypass" -Force)

    # not necessary
    # $groups = "Licensing_Office365_Student_A5", "Licensing_Office365_Student_WinEnterprise_A5"


    if (@(Get-ADUser -Filter { SamAccountName -eq $username }).Count -eq 1) {
    Write-host "$username has been succesfully created" -ForegroundColor Green
    Write-host "You will need to manually assign a quick-pin"
    Write-Host "You will need to assign Adobe License"
     
    }


elseif (@(Get-ADUser -Filter { SamAccountName -eq $username }).Count -eq 0) {
    Write-warning "$username has not been created, please check for any errors"
}

Read-Host -Prompt "Press Enter to exit"