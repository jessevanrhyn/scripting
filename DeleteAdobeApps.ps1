$folderPath = "C:\Program Files\Adobe"
$totalClearedSpace = 0

# list all subfolders
$subfolders = Get-ChildItem -Path $folderPath -Directory

# loop
foreach ($subfolder in $subfolders) {
    $subfolderName = $subfolder.Name

    # skip essential folders
    if ($subfolderName -like "*Creative Cloud*" -or $subfolderName -like "*Common*") {
        continue
    }

    # prompt
    Write-Host "Folder name: $subfolderName" -ForegroundColor Green

    # Calculate and display the folder size
    $folderSize = (Get-ChildItem -Path $subfolder.FullName -Recurse -File | Measure-Object -Property Length -Sum).Sum
    $folderSizeGB = [Math]::Round($folderSize / 1GB, 2)
    Write-Host "Folder size: $folderSizeGB GB" -ForegroundColor DarkGreen

    $confirmation = Read-Host "
Delete this folder? (yes/no)"

    if ($confirmation -in "yes", "y") {
        $finalConfirmation = Read-Host "Are you sure you want to delete this folder? (yes/y or no/n)"

        if ($finalConfirmation -in "yes", "y") {
            # delete
            Remove-Item -Path $subfolder.FullName -Recurse -Force
            Write-Host "Folder deleted." -ForegroundColor Green

            # update sum
            $totalClearedSpace += $folderSize
        } else {
            Write-Host "Folder not deleted." -ForegroundColor Red
        }
    } else {
        Write-Host "Folder not deleted." -ForegroundColor Red
    }
}

# display total cleared space
$totalClearedSpaceGB = [Math]::Round($totalClearedSpace / 1GB, 2)
Write-Host "Total cleared space: $totalClearedSpaceGB GB" -ForegroundColor Cyan
