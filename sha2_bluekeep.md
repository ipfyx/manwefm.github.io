##### Bluekeep, why would you still be vulnerable? SHA2 signing.

Patch management is a pain, and the more obsolete the OS, the trickier it becomes. Windows 7 and 2008 R2 (Windows  6.1) are due to reach End Of Life (EOL) on 14 January 2020 (tomorrow at the time of this writing) but your computers may not have been patched since August 2019 if you haven’t been careful.

Indeed, August 2019 was the last month where Microsoft KB were signed using SHA1. Since then, KBs are only signed using SHA2, but this hash function must be installed on Windows 6.1 in order for your computers and servers to install them. Otherwise they will fail with error code 0x80092004 (CRYPT_E_NOT_FOUND).

Since Windows Server 2012R2, this hash function is already included so there is nothing to worry about for 2012R2, 2016 and 2019.
Unfortunately, in August and September 2019, Bluekeep, a critical security vulnerability on Microsoft’s Remote Desktop Protocol, which allow s for the possibility of remote code execution as system, was released, and patched by Microsoft during those two months. Therefore, if some computers running Windows 6.1 were not up to date on August 2019, they are vulnerable to Bluekeep since September 2019. I hope it’s not your DC, or your WSUS…

But don’t panic, here is what you can do :
-	Find the machines in error
-	Fix the machines in error

### Finding the machines in error :

If you’re using WSUS to patch your domain, I got something for you. Since WSUS Report Viewer is awfully slow and a pain to use, I developed a quick script using Powershell to retrieve every computer in error. This script must be run as Administrator on the WSUS server delivering the patch to the clients, it was only tested on WSUS running on Windows 2012R2 or later. The script only looks for computers in error and writes their names, the error codes and the KBs in failure in a CSV file.

SCCM is out of scope in this article but aleardy provides the necessary dashboard if you’re patching with it. It can be used alongside WSUS to quickly deploy a KB on you infrastructure.

Here is an example, followed by a possible result and the script itself. You can also [download it](https://manwefm.github.io/wsus_computers_in_error.ps1).

```powershell
.\wsus_computers_in_error.ps1 –ServerName wsus.ipfyx.fr –ServerPort 8531 –RelativeTime -168 –ErrorCode 0x80092004 –CsvPath « .\computer_no_sha2_$(Get-Date –Format yyyy-MM-dd).csv »
```

```powershell
<#
    .SYNOPSIS
    Retrieve every computer in error when installing a Microsoft KB, with a specifi error code or not (SHA2 error : 0x80092004)

    .PARAMETER ErrorCode
    Error code

    .PARAMETER ServerName
    Name of the WSUS Server

    .PARAMETER ServerPort
    Port of the WSUS Server (8531 if it is using SSL, else 8530)

    .PARAMETER RelativeTime
    Relative time between now and a past time (ex : -24 is -24h)

    .PARAMETER CsvPath
    Output file in CSV

    .NOTES
    (c) ipfyx 2019
    version 1.5

    Example
    .\wsus_computers_in_error.ps1 -ServerName <Server> -ServerPort 8531 -RelativeTime -168 -Errorcode 0x80092004 -CsvPath ".\computer_no_sha2_$(Get-Date -Format yyyy-MM-dd).csv"

#>

# This script must be run with Administrator privileges.
#Requires -RunAsAdministrator

Param([Parameter(Mandatory=$True)][string]$ServerName, [Parameter(Mandatory=$True)][string]$ServerPort, 
[Parameter(Mandatory=$False)][int32]$RelativeTime=-48, [Parameter(Mandatory=$False)][string]$Errorcode='',
[Parameter(Mandatory=$True)][string]$CsvPath)

Function Get_Computer_Scope {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $Wsus,

    [Parameter(Mandatory=$False)]
    [string]
    $InstallationStates = 'Failed',

    [Parameter(Mandatory=$False)]
    [boolean]
    $IncludeDownstreamComputerTargets = $true
    )

    # Retrieve every computer in error according to WSUS reports
    $computerScope = new-object Microsoft.UpdateServices.Administration.ComputerTargetScope
    $computerScope.IncludedInstallationStates = $InstallationStates

    # Retrieve every compuer in error accoring to downtream servers too
    $computerScope.IncludeDownstreamComputerTargets = $InstallationStates

    $Wsus.GetComputerTargets($computerScope)
}

Function Get_Event_History {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    $Wsus,

    [Parameter(Mandatory=$True)]
    [string]
    $RelativeTime,

    [Parameter(Mandatory=$False)]
    [string]
    $InstallationStates = 'Failed',

    [Parameter(Mandatory=$False)]
    [string]
    $ErrorCode = ''
    )

    
    # Quelques messages d'erreur sont juste "Installation Failure: Windows failed to install the following update with error %1: %2"
    # Et l'updateID associé n'existe pas dans la bdd (2ce8a11d-7f90-4489-92f3-a202585b793b), pourquoi, je sais pas, mais ca fout le sbeul

    # Retrieve every computer in error, no matter the error code, if the error code is not spectified
    if ($ErrorCode -eq '') {

        $Wsus.GetUpdateEventHistory("$((Get-Date).AddHours($RelativeTime))","$(Get-Date)")|
                    Where-Object {$_.Status -eq $InstallationStates}|
                    Select-Object ComputerId, CreationDate, Message, ErrorCode, UpdateId
    }
    else {
        $Wsus.GetUpdateEventHistory("$((Get-Date).AddHours($RelativeTime))","$(Get-Date)")|
                    Where-Object {$_.Status -eq $InstallationStates}|
                    Where-Object {$_.ErrorCode -eq $Errorcode} |
                    Select-Object ComputerId, CreationDate, Message, ErrorCode, UpdateId
    }
}


If ($ServerPort -eq '8531') {
    $Wsus = Get-WsusServer -Name $ServerName -PortNumber $ServerPort -UseSsl
} Else {
    $Wsus = Get-WsusServer -Name $ServerName -PortNumber $ServerPort
}

$ComputersInFailure = Get_Computer_Scope -Wsus $Wsus

$ComputersAffected = @{}

$ErrorMessages = Get_Event_History -RelativeTime $RelativeTime -ErrorCode $ErrorCode -Wsus $Wsus
$ErrorMessages | ForEach-Object {

  $ComputerId = $_.ComputerId
  $ComputerWithError = $ComputersInFailure | Where-Object {$_.id -eq $ComputerId}

  if($ComputerWithError -ne $null) {
  
      try {
        # Retrieve the Knowledge Base number associated with the update guid
        $updateGuid = $_.UpdateId.UpdateId.guid
        $updateId = New-Object Microsoft.UpdateServices.Administration.UpdateRevisionId($updateGuid)
        $update = $wsus.GetUpdate($updateId)

        # A computer could fail multiple KB install so the key to distinguish every case is FullDomaineName+KB
        $Key = $ComputerWithError.FullDomainName+[System.Convert]::ToString($_.ErrorCode,16)+$update.KnowledgebaseArticles[0]

        if ($ComputersAffected.ContainsKey($Key)) {

            # We only want the last report in error
            if ($ComputerWithError.LastReportedStatusTime -gt $ComputersAffected[$Key].LastReportedStatusTime) {

                $ComputersAffected[$Key]=    
                [pscustomobject]@{  
                FullDomaineName = $ComputerWithError.FullDomainName
                IPAddress = $ComputerWithError.IPAddress
                OSDescription = $ComputerWithError.OSDescription
                ErrorCode = [System.Convert]::ToString($_.ErrorCode,16)
                LastReportedStatusTime = $ComputerWithError.LastReportedStatusTime
                UpdateTitle = $update.Title
                KB = $update.KnowledgebaseArticles[0]
                ArrivalDate = $update.ArrivalDate

                }                
            }
          
        } else {

            $ComputersAffected[$Key]=    
            [pscustomobject]@{  
            FullDomaineName = $ComputerWithError.FullDomainName
            IPAddress = $ComputerWithError.IPAddress
            OSDescription = $ComputerWithError.OSDescription
            ErrorCode = [System.Convert]::ToString($_.ErrorCode,16)
            LastReportedStatusTime = $ComputerWithError.LastReportedStatusTime
            UpdateTitle = $update.Title
            KB = $update.KnowledgebaseArticles[0]
            ArrivalDate = $update.ArrivalDate

            }
        }

      }
      catch [Microsoft.UpdateServices.Administration.WsusObjectNotFoundException]{
            # Some "ghost" reports can mess up the script
            # We don't do anything
      }
   }

}

$ComputersAffected.Values | Export-Csv -Encoding UTF8 -Path $CsvPath

```

```powershell
#TYPE System.Management.Automation.PSCustomObject
"FullDomaineName","IPAddress","OSDescription","ErrorCode","LastReportedStatusTime","UpdateTitle","KB","ArrivalDate"
"toto.ipfyx.fr","1.1.1.1","Windows 7","80070643","01/01/1970 00:00:00","Cumulative Security Update","4474333","01/01/1970 01:00:00"
```
### Fixing the machines in error :

Indeed, Windows 6.1 is due to reach End Of Life (EOL) on 14 January 2020, so why bother ? Well, Bluekeep is such a critical vulnerability that you should not neglect. After that, you should hurry to upgrade your server to at least Windows 2012 R2, and you computers to Windows 10.

In the meantime, to fix this issue, you should install : 

- 2008R2 et 7 :
  - KB 4474419 (cumulative security update from July 2019 or before, last KB signed using SHA1 for Windows 2008R2)
  - KB 4490628 (Stack update from March 2019)
- 2008 :
  - KB 4474419 (cumulative security update from June 2019, last KB signed using SHA1 for Windows 2008)
  - KB 4493730 (Stack update from April 2019)
  
### Quick bonus :

If you don’t specify any error code to the script, it will return every computer in error, whatever the error code. You can therefore use this script to diagnose your patch management. The CSV result could, for example, be put in splunk to build dashboard.

```powershell
.\wsus_computers_in_error.ps1 –ServerName wsus.ipfyx.fr –ServerPort 8531 –RelativeTime -168 ––CsvPath « .\computer_in_error_$(Get-Date –Format yyyy-MM-dd).csv »
```
