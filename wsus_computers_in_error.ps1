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
