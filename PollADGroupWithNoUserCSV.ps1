<# AD Groups with no users

Polls Active Directory for a list of groups that have no users and exports them to a CSV

Exports to C:\temp, creates one such folder if it doesn't exist

#>



#define scope
$searchBase = "DC=curric,DC=stfx"

# search
$groups = Get-ADGroup -SearchBase $searchBase -Filter * -Properties Members |
    Where-Object { $_.Members.Count -eq 0 }

# make array to store
$result = @()

# collect info and append to array
foreach ($group in $groups) {
    $groupInfo = [PSCustomObject]@{
        GroupName = $group.Name
        GroupDN = $group.DistinguishedName
        GroupSID = $group.SID.Value
    }

    $result += $groupInfo
}

# greater exports than china

$path = "C:\temp"

if (Test-Path $path) {
    $result | Export-Csv -Path "C:\temp\groups-no-users.csv" -NoTypeInformation
}
else {
    New-Item -ItemType Directory -Path $path
    Write-Host "see C:\temp for output"
    $result | Export-Csv -Path "C:\temp\groups-no-users.csv" -NoTypeInformation
}