# Check if the script is running as an administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script as an administrator
    Start-Process PowerShell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    # Exit the current script
    exit
}

# Import the required modules
$modulesToInstall = @(
    @{
        Name = 'WindowsAutoPilotIntune'
        WarningMessage = 'Failed to install the WindowsAutoPilotIntune module'
    },
    @{
        Name = 'Microsoft.Graph.Intune'
        WarningMessage = 'Failed to install the Microsoft.Graph.Intune module'
    },
    @{
        Name = 'AzureAD'
        WarningMessage = 'Failed to install the AzureAD module'
    }
)

foreach ($module in $modulesToInstall) {
    if (-not (Get-Module -ListAvailable -Name $module.Name)) {
        try {
            # Install the module
            Install-Module -Name $module.Name -Force
        } catch {
            Write-Warning $module.WarningMessage
            $restart = Read-Host -Prompt 'Do you want to restart the script as an administrator? (y/n)'
            if ($restart -eq 'y') {
                # Restart the script as an administrator
                Start-Process PowerShell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
            } else {
                # End the script
                return
            }
        }
    }
}

# Display a message to the user
Write-Host "Make sure to have your Intune role activated, and when prompted for sign-in use your personal CA account. Press enter to continue."
Read-Host

# Get the credentials
$credential = Get-Credential




# Connect to Microsoft Graph using the provided credentials
try {
    Connect-MSGraph -Credential $credential
} catch {
    Write-Warning "Failed to connect to Microsoft Graph"
    $restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'
    if ($restart -eq 'y') {
        # Restart the script
        & $PSCommandPath
    } else {
        # End the script
        return
    }
}

# Connect to AzureAD using the provided credentials
try {
    Connect-AzureAD -Credential $credential
} catch {
    Write-Warning "Failed to connect to AzureAD"
    $restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'
    if ($restart -eq 'y') {
        # Restart the script
        & $PSCommandPath
    } else {
        # End the script
        return
    }
}


# Prompt for the serial number or name of the target device
do {
    $deviceIdentifier = Read-Host -Prompt 'Enter the serial number of the device to be removed (4-15 characters, no * character and no spaces)'

    # Check if the device identifier meets the required criteria
    $isValidFormat = $deviceIdentifier -match '^[^\s\*]{4,15}$'

    if (-not $isValidFormat) {
        Write-Host "Incorrect Text Format. Please retry."
        continue
    }

    # Check if the device exists in AutoPilot
    $autoPilotDevice = Get-AutoPilotDevice | Where-Object { $_.SerialNumber -eq $deviceIdentifier }
    if ($autoPilotDevice) {
        Write-Host "Device found in AutoPilot"
    } else {
        Write-Host "Device not found in AutoPilot"
    }


# Check if the device exists in Intune
$intuneDevice = Get-IntuneManagedDevice -Filter "serialNumber eq '$deviceIdentifier'"
if ($intuneDevice) {
    Write-Host "Device found in Intune"

    # Find the AzureAD device based on its display name
    $azureADDevice = Get-AzureADDevice -Filter "DisplayName eq '$($intuneDevice.deviceName)'"
    if ($azureADDevice) {
        Write-Host "Device found in AzureAD"
    } else {
        Write-Host "Device not found in AzureAD"
    }
} else {
    Write-Host "Device not found in Intune"

    # Loop through multiple prefixes to find the AzureAD device
    $prefixes = @("SFX-", "L13-", "380-", "390-")
    foreach ($prefix in $prefixes) {
        $azureADDevice = Get-AzureADDevice -Filter "DisplayName eq '$($prefix + $deviceIdentifier)'"
        if ($azureADDevice) {
            Write-Host "Device found in AzureAD with prefix $prefix"
            break
        }
    }
    if (-not $azureADDevice) {
        Write-Host "Device not found in AzureAD with any prefix"

        # Check for the device in AzureAD without a prefix
        $azureADDevice = Get-AzureADDevice -Filter "DisplayName eq '$deviceIdentifier'"
        if ($azureADDevice) {
            Write-Host "Device found in AzureAD without prefix"
        } else {
            Write-Host "Device not found in AzureAD without prefix"
        }
    }
}

$retry = Read-Host -Prompt 'Do you want to Continue? (y/n)'
} while ($retry -eq 'n')


# Check for multiple devices in $AzureADDevice, $intuneDevice, and $autoPilotDevice
if ($AzureADDevice.Count -gt 1 -or $intuneDevice.Count -gt 1 -or $autoPilotDevice.Count -gt 1) {
    Write-Warning "More than 1 device found. You need to manually delete the appropriate device."

    # Prompt the user to restart the script
    $restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'

    if ($restart -eq 'y') {
        # Restart the script
        & $PSCommandPath
    } else {
        # Keep the PowerShell window open
        pause
    }

    # Exit the current instance of the script
    exit
}

# Criteria 1: Device found in AutoPilot, Intune, and Azure AD
if ($null -ne $autoPilotDevice -and $null -ne $intuneDevice -and $null -ne $azureADDevice) {
    # Code for Criteria 1
    Write-Host "Device found in AutoPilot, Intune, and AzureAD"
    $autoPilotDevice | Format-List
    $intuneDevice | Format-List
    $azureADDevice | Format-List


# Check for multiple devices in $AzureADDevice, $intuneDevice, and $autoPilotDevice
if ($AzureADDevice.Count -gt 1 -or $intuneDevice.Count -gt 1 -or $autoPilotDevice.Count -gt 1) {
    Write-Warning "More than 1 device found, ending script due to potential Error - You need to manually delete appropriate device"
    return
}

    $deleteDevices = Read-Host -Prompt 'Do you want to delete these devices? (y/n)'
    if ($deleteDevices -eq 'y') {
    
    #Display Devices to be deleted
        Write-Host "Devices to be deleted:"
        Write-Host "AutoPilot device: $($autoPilotDevice.SerialNumber)"
        Write-Host "Intune device: $($intuneDevice.deviceName)"
        Write-Host "AzureAD device: $($azureADDevice.DisplayName)"
    

        $confirmDeletion = Read-Host -Prompt 'Are you sure you want to proceed with the deletion? This action is irreversible. (y/n)'
        if ($confirmDeletion -eq 'y') {
            # Delete devices
           
            # Delete device from Intune
            $intuneDevice | Remove-IntuneManagedDevice
            Write-Host "The device was successfully removed from Intune" -ForegroundColor Green

            # Delete device from AzureAD
            Remove-AzureADDevice -ObjectId $azureADDevice.ObjectId
            Write-Host "The device was successfully removed from AzureAD" -ForegroundColor Green

            # Sleep for 5 seconds
            Start-Sleep -Seconds 5


            # Delete device from AutoPilot
            $autoPilotDevice | Remove-AutoPilotDevice
            Write-Host "The device was successfully removed from AutoPilot" -ForegroundColor Green

            # Prompt to restart or end the script
            $restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'
            if ($restart -eq 'y') {
                # Restart the script
                & $PSCommandPath
            } else {
                # Keep the PowerShell window open
                pause
            }
        } else {
            Write-Host "Deletion canceled. Devices will not be deleted."
        }
    }
}

# Criteria 2: Device found in AutoPilot Only

elseif ($null -ne $autoPilotDevice -and $null -eq $intuneDevice -and $null -eq $azureADDevice) {
    # Code for Criteria 2
    Write-Host "Device found in AutoPilot only"
    $autoPilotDevice | Format-List
    
    # Check for multiple devices in $AzureADDevice, $intuneDevice, and $autoPilotDevice
if ($AzureADDevice.Count -gt 1 -or $intuneDevice.Count -gt 1 -or $autoPilotDevice.Count -gt 1) {
    Write-Warning "More than 1 device found, ending script due to potential Error - You need to manually delete appropriate device"
    return
}

    $deleteAutoPilot = Read-Host -Prompt 'Device is only found in AutoPilot. Do you want to attempt to delete the device? (y/n)'
    if ($deleteAutoPilot -eq 'y') {

    #Display Devices to be deleted
        Write-Host "Devices to be deleted:"
        Write-Host "AutoPilot device: $($autoPilotDevice.SerialNumber)"
        


        $confirmDeletion = Read-Host -Prompt 'Are you sure you want to proceed with the deletion? This action is irreversible. (y/n)'
        if ($confirmDeletion -eq 'y') {
            # Check if the device is enrolled in AutoPilot before attempting removal.
            if ($autopilotDevice.EnrollmentState -eq "Enrolled") {
                Write-Host "The device is enrolled. Skipping removal from AutoPilot."
            } else {
                try {
                    # Attempt to remove the device from AutoPilot and output success message if successful.
                    $autopilotDevice | Remove-AutoPilotDevice
                    Write-Host "The device was successfully removed from AutoPilot."
                } catch {
                    Write-Warning "Failed to remove device from AutoPilot."
                }
            }

            # Prompt to restart or end the script
            $restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'
            if ($restart -eq 'y') {
                # Restart the script
                & $PSCommandPath
            } else {
                # Keep the PowerShell window open
                pause
            }
        } else {
            Write-Host "Deletion canceled. Device will not be deleted from AutoPilot."
        }
    }
}

# Criteria 3: Device found in Intune and AutoPilot only
elseif ($null -ne $autoPilotDevice -and $null -ne $intuneDevice -and $null -eq $azureADDevice) {
    # Code for Criteria 3
    Write-Host "Device found in Intune and AutoPilot only"
    $intuneDevice | Format-List
    $autoPilotDevice | Format-List


    # Check for multiple devices in $AzureADDevice, $intuneDevice, and $autoPilotDevice
if ($AzureADDevice.Count -gt 1 -or $intuneDevice.Count -gt 1 -or $autoPilotDevice.Count -gt 1) {
    Write-Warning "More than 1 device found, ending script due to potential Error - You need to manually delete appropriate device"
    return
}

    $deleteDevices = Read-Host -Prompt 'Do you want to delete these devices? (y/n)'
    if ($deleteDevices -eq 'y') {
    
    #Display Devices to be deleted
        Write-Host "Devices to be deleted:"
        Write-Host "AutoPilot device: $($autoPilotDevice.SerialNumber)"
        Write-Host "Intune device: $($intuneDevice.deviceName)"
       
    

        $confirmDeletion = Read-Host -Prompt 'Are you sure you want to proceed with the deletion? This action is irreversible. (y/n)'
        if ($confirmDeletion -eq 'y') {
            # Delete devices
           
            # Delete device from Intune
            $intuneDevice | Remove-IntuneManagedDevice
            Write-Host "The device was successfully removed from Intune" -ForegroundColor Green

            # Sleep for 5 seconds
            Start-Sleep -Seconds 5


            # Delete device from AutoPilot
            $autoPilotDevice | Remove-AutoPilotDevice
            Write-Host "The device was successfully removed from AutoPilot" -ForegroundColor Green

            # Prompt to restart or end the script
            $restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'
            if ($restart -eq 'y') {
                # Restart the script
                & $PSCommandPath
            } else {
                # Keep the PowerShell window open
                pause
            }
        } else {
            Write-Host "Deletion canceled. Devices will not be deleted."
        }
    }
}



# Criteria 4: Device found in AutoPilot and Azure AD only
elseif ($null -ne $autoPilotDevice -and $null -eq $intuneDevice -and $null -ne $azureADDevice) {
    # Code for Criteria 4
    Write-Host "Device found in AutoPilot and AzureAD only"
    $autoPilotDevice | Format-List
    $azureADDevice | Format-List
# Check for multiple devices in $AzureADDevice, $intuneDevice, and $autoPilotDevice
if ($AzureADDevice.Count -gt 1 -or $intuneDevice.Count -gt 1 -or $autoPilotDevice.Count -gt 1) {
    Write-Warning "More than 1 device found, ending script due to potential Error - You need to manually delete appropriate device"
    return
}

    $deleteDevices = Read-Host -Prompt 'Do you want to delete these devices? (y/n)'
    if ($deleteDevices -eq 'y') {

    #Display Devices to be deleted
        Write-Host "Devices to be deleted:"
        Write-Host "AutoPilot device: $($autoPilotDevice.SerialNumber)"
       
        Write-Host "AzureAD device: $($azureADDevice.DisplayName)"


        $confirmDeletion = Read-Host -Prompt 'Are you sure you want to proceed with the deletion? This action is irreversible. (y/n)'
        if ($confirmDeletion -eq 'y') {
            # Delete devices
         
            # Delete device from AzureAD
            Remove-AzureADDevice -ObjectId $azureADDevice.ObjectId

            Write-Host "The device was successfully removed from AzureAD" -ForegroundColor Green

            # Sleep for 5 seconds
            Start-Sleep -Seconds 5

            # Delete device from AutoPilot
            $autoPilotDevice | Remove-AutoPilotDevice
            Write-Host "The device was successfully removed from AutoPilot" -ForegroundColor Green

            # Prompt to restart or end the script
            $restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'
            if ($restart -eq 'y') {
                # Restart the script
                & $PSCommandPath
            } else {
                # Keep the PowerShell window open
                pause
            }
        } else {
            Write-Host "Deletion canceled. Devices will not be deleted."
        }
    }
}

# Criteria 5: Device found in Intune and Azure AD only
elseif ($null -eq $autoPilotDevice -and $null -ne $intuneDevice -and $null -ne $azureADDevice) {
    # Code for Criteria 5
    Write-Host "Device found in Intune and AzureAD only"
    $intuneDevice | Format-List
    $azureADDevice | Format-List
# Check for multiple devices in $AzureADDevice, $intuneDevice, and $autoPilotDevice
if ($AzureADDevice.Count -gt 1 -or $intuneDevice.Count -gt 1 -or $autoPilotDevice.Count -gt 1) {
    Write-Warning "More than 1 device found, ending script due to potential Error - You need to manually delete appropriate device"
    return
}

    $deleteDevice = Read-Host -Prompt 'Do you want to delete this device from Intune and AzureAD? (y/n)'
    if ($deleteDevice -eq 'y') {

    #Display Devices to be deleted
        Write-Host "Devices to be deleted:"
    
        Write-Host "Intune device: $($intuneDevice.deviceName)"
        Write-Host "AzureAD device: $($azureADDevice.DisplayName)"


        $confirmDeletion = Read-Host -Prompt 'Are you sure you want to proceed with the deletion? This action is irreversible. (y/n)'
        if ($confirmDeletion -eq 'y') {
            # Delete device from Intune
            $intuneDevice | Remove-IntuneManagedDevice
            Write-Host "The device was successfully removed from Intune" -ForegroundColor Green


            # Delete device from AzureAD
            Remove-AzureADDevice -ObjectId $azureADDevice.ObjectId
            Write-Host "The device was successfully removed from AzureAD" -ForegroundColor Green

            # Prompt to restart or end the script
            $restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'
            if ($restart -eq 'y') {
                # Restart the script
                & $PSCommandPath
            } else {
                # Keep the PowerShell window open
                pause
            }
        } else {
            Write-Host "Deletion canceled. Device will not be deleted from Intune and AzureAD."
        }
    }
}


# Criteria 6: Device found in AzureAD Only

elseif ($null -ne $AzureADdevice -and $null -eq $intuneDevice -and $null -eq $azureADDevice) {
    # Code for Criteria 2
    Write-Host "Device found in AzureAD only"
    $AzureADdevice | Format-List
    
    # Check for multiple devices in $AzureADDevice, $intuneDevice, and $autoPilotDevice
if ($AzureADDevice.Count -gt 1 -or $intuneDevice.Count -gt 1 -or $autoPilotDevice.Count -gt 1) {
    Write-Warning "More than 1 device found, ending script due to potential Error - You need to manually delete appropriate device"
    return
}

    $deleteDevice = Read-Host -Prompt 'Do you want to delete this device from AzureAD? (y/n)'
    if ($deleteDevice -eq 'y') {

    #Display Devices to be deleted
        Write-Host "Devices to be deleted:"
    
      
        Write-Host "AzureAD device: $($azureADDevice.DisplayName)"


        $confirmDeletion = Read-Host -Prompt 'Are you sure you want to proceed with the deletion? This action is irreversible. (y/n)'
        if ($confirmDeletion -eq 'y') {
           

            # Delete device from AzureAD
            Remove-AzureADDevice -ObjectId $azureADDevice.ObjectId
            Write-Host "The device was successfully removed from AzureAD" -ForegroundColor Green

            # Prompt to restart or end the script
            $restart = Read-Host -Prompt 'Do you want to restart the script? (y/n)'
            if ($restart -eq 'y') {
                # Restart the script
                & $PSCommandPath
            } else {
                # Keep the PowerShell window open
                pause
            }
        } else {
            Write-Host "Deletion canceled. Device will not be deleted from Intune and AzureAD."
        }
    }
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