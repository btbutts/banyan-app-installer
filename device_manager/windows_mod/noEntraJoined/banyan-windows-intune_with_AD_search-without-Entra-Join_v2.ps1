
<#PSScriptInfo

.VERSION 1.0

.GUID b025e06e-29ac-4099-9fa2-d897a454a743

.AUTHOR Original Developer: SonicWall, Inc. (formerly Banyan Security), Modified by: Brian Butts

.COMPANYNAME SonicWall, Inc.

.COPYRIGHT

.TAGS
unofficial-version
supports_On-Premise_AD-DS

.LICENSEURI

.PROJECTURI https://github.com/banyansecurity/app-installer/blob/main/device_manager/banyan-windows-intune.ps1

.ICONURI https://docs.banyansecurity.io/img/release-notes/cse-desktop-tray.png

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
The script installs the CSE app 'Banyan app' on Windows machines.
It was originally intended only for Intune managed endpoings that were Entra ID joined, specifically.
It has been modified to work in other invironments as well, including:
• On-premise Joined Machines
• Machines with only local user accounts
• Machines that are Intune managed, but not Entra ID joined


The last improvement to the script is that the CSE developer's previous implementation could only
determine what user to run the installation and startup sequence as if the user was locally logged
into the machine. A sequence has been added that adopts 'query.exe' to obtain the same information
such that the script can be installed remotely as well. This provides better compatbility in
virtualized and remote computing environments.


This version of the script is not officially maintained by SonicWall, Inc. (formerly Banyan Security).
It has been modified to provide better compatibility for legacy  and hybrid evironments but is
provided entirely as-is. Note that it is not officially supported by SonicWall.


This script does not require any Third-Party software to function.
• Third-Party software, for the purposes of this script, is defined as software not developed
  by SonicWall, Inc. (formerly Banyan Security) or by Microsoft Corporation.
• The PowerShell modules and cmd-lets used in this script are packaged by Microsoft Corporation's
  default installation of PowerShell.
• The script will download and install the latest version of the standard Banyan app for Windows.
• The same Banyan app is available for download from:
  https://getcseapp.sonicwall.com/download_app/

.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 The script installs the CSE app (Banyan app) on Windows machines 

.SYNOPSIS
The script adhere's to the original developer's sequence for obtaining the necessary
logged-in user's attributes from the local machine, using a specific Entra ID registry key and the
'Get-WMIObject' cmd-let. However, this does not work for all environments for a number of reasons.
The new modifications allow this script to work in many other environment configurations
If the local logged-in user is not Entra joined, the script will query the registry's session cache
for all previous users that have ever logged into the local machine.
• If there is just one user found, then that is automatically the selected user for the CSE install
  script, and the local user's DN, UPN, and DisplayName attributes are pulled from that registry key.
• If there are more than one historical users, the logged in user (including now for terminal services
  users, Citrix VDI, VMware Horizon, etc..., instead of users that are physically logged in as per the
  CSE developer's original defaults) is queried against the local session cache registry key to gather
  the active user's DN, UPN, and DisplayName.
• If the active user's attributes had to be pulled from the local registry's session cache, rather than
  the Entra ID join reg keys, then the script will query AD DS for the user's Mail attribute to use that,
  preferably, for the user's email address, in case that attribute differs from the local, active user's UPN.
• If AD DS is not available, the script will default to the UPN for the email. Though that is not always
  preferable, it is the fallback option.

.EXAMPLE
The script should be run from an elevated PowerShell.
PowerShell version 5.1 or greater is reccomended

Run the following:
.\banyan-windows-intune_with_AD_search.ps1

#>
Param()


# Run as administrator

################################################################################
# Banyan Zero Touch Installation
# Confirm or update the following variables prior to running the script

# Deployment Information
# Obtain from the Banyan admin console: Settings > App Deployment
$INVITE_CODE = "insert-invite-code-in-quotes"
$DEPLOYMENT_KEY = "insert-CSE-Deployment-Key-in-quotes"
#$APP_VERSION = "<YOUR_APP_VERSION (optional)>"

# Device Registration and Banyan App Configuration
# Check docs for more options and details:
# https://docs.banyansecurity.io/docs/feature-guides/manage-users-and-devices/device-managers/distribute-desktopapp/#mdm-config-json
$DEVICE_OWNERSHIP = "C"
$CA_CERTS_PREINSTALLED = $false
$SKIP_CERT_SUPPRESSION = $false
$IS_MANAGED_DEVICE = $true
$DEVICE_MANAGER_NAME = "Intune"
$HIDE_SERVICES = $false
$DISABLE_QUIT = $false
$START_AT_BOOT = $true
$AUTO_LOGIN = $true
$HIDE_ON_START = $true
$DISABLE_AUTO_UPDATE = $false

# User Information for Device Certificate
$MULTI_USER = $false

# Preview Feature: Allow App via NetFirewallRule for Windows Firewall.
$ALLOW_APP = $true

# Custom (optional) settings:
$ENDPOINT_REPORT_INTERVAL = "7"
#INTUNE_UDID = $INTUNE_UDID ###Is defined below###
$TOKEN_NOTIFY = "120"


################################################################################


$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (! $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be with admin privilege"
    exit 1
}

if (!$INVITE_CODE -or !$DEPLOYMENT_KEY) {
    Write-Host "Usage: "
    Write-Host "$PSCommandPath <INVITE_CODE> <DEPLOYMENT_KEY> <APP_VERSION (optional>"
    exit 1
}

if (!$APP_VERSION) {
    Write-Host "Checking for latest version of app"
    $APP_VERSION = if ((Invoke-RestMethod -Uri "https://www.banyanops.com/app/releases/latest.yml") -match "version: (.+)") {$matches[1].Trim()}
}

Write-Host "Installing with invite code: $INVITE_CODE"
Write-Host "Installing using deploy key: *****"
Write-Host "Installing app version: $APP_VERSION"


# Original line to query logged in user. (It apparently cannot work on remote users thus we modify with the following...)
$logged_on_user = Get-WMIObject -class Win32_ComputerSystem | Select-Object -expand UserName


############################################################
########### Begin Alternative User Identification ##########
############################################################
# Do not fill in these variables
$DownLevel_RegUserName = ""
$DisplayName_RegUserName = ""
$CN_RegUserName = ""
$UserUPN_RegUserName = ""
$ADUserAttributes = ""
$IsADsourced = ""

# Begin Declarable Variables
# Uncomment and define as needed
# Do not leave the following variables un-commented if declared as $null
#$UserDC = "example.org"

function GetUserAttributes {
    # Searches AD DS for user attributes
    # Supply username, First and/or Last Names, to -Name "" argument
    # GetUserInfo -Name "Joe Smith"
    # GetUserInfo -Name "jsmith"
    param (
        [string]$name
    )
    $filter = "(&(|(objectcategory=user))(|(userprincipalname=$name)(samaccountname=$name)(name=$name)(sn=$name)(givenname=$name)(mail=$name)))"
    $searcher = [adsisearcher]$filter
    $searcher.PageSize = 256
    $searcher.PropertiesToLoad.AddRange(('name', 'displayname', 'sn', 'givenname', 'distinguishedname', 'samaccountname', 'userprincipalname', 'mail', 'proxyaddresses'))
    $(foreach ($object in $searcher.FindAll()) {
        New-Object -TypeName PSObject -Property @{
            LastName          = [string]$object.properties.sn
            FirstName         = [string]$object.properties.givenname
            DisplayName       = [string]$object.properties.displayname
            Name              = [string]$object.properties.name
            DistinguishedName = [string]$object.properties.distinguishedname
            SamAccountName    = [string]$object.properties.samaccountname
            UserPrincipalName = [string]$object.properties.userprincipalname
            Mail              = [string]$object.properties.mail
            ProxyAddresses    = [string[]]$object.properties.proxyaddresses
        }
    }) | Select-Object displayname, name, lastname, firstname, distinguishedname, samaccountname, userprincipalname, mail, proxyaddresses
}

function DiscoverLoggedonUser {
    # Obtain user identeties that have logged into local machine
    $UserSessionRegSource = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData"
    $UserSessionRegKey = Get-ChildItem -path $UserSessionRegSource
    $UserSessionRegKey = $UserSessionRegKey -replace "HKEY_LOCAL_MACHINE","HKLM:"
    $RegUserSessions = Get-ItemProperty -Path $UserSessionRegKey
    $RegUserNamesSAM = $RegUserSessions.LoggedOnSAMUser | Sort-Object | Get-Unique
    # If machine has ever had more than one user log into the machine, then
    # run further processing to narrow down to just the current active user
    if ($RegUserNamesSAM.count -gt 1) {
        # Query current logged-in username and add data to array: $FinalUserArray
        $UserQueryRaw = query.exe user /server:$env:COMPUTERNAME
        $UserQueryCSV = $UserQueryRaw.Trim().Replace("  ",",").Replace(", ",",").Replace(" ,",",").Replace(",,,,,",",").Replace(",,,,",",").Replace(",,,",",").Replace(",,",",")
        $UserCSVArray = $UserQueryCSV -split "`n"
        # If errors are encountered when determining the logged-in user from query.exe, comment out the line immediately
        # followling the first break below and uncomment the remaining lines in this DiscoverLoggedinUser function until
        # you reach the following break:
        ##############\__________break__________/##############
        $FinalUserArray = $UserCSVArray | ConvertFrom-Csv -Header "USERNAME","SESSIONNAME","ID","STATE","IDLE_TIME","LOGON_TIME" | Select-Object -Skip 1
        ##Adjust CSV formatting with extra comma if needed
        #for ($i=0; $i -lt $UserCSVArray.Length; $i++) {
        #    # Count the number of commas in the row
        #    $commaCount = ([regex]::Matches($UserCSVArray[$i], ",")).Count
        #    # If there are only four commas, replace the first comma with two commas
        #    if ($commaCount -eq 4) {
        #        $firstCommaIndex = $UserCSVArray[$i].IndexOf(",")
        #        $UserCSVArray[$i] = $UserCSVArray[$i].Insert($firstCommaIndex + 1, ",")
        #    }
        #}
        #InitUserArray = $UserCSVArray | ConvertFrom-Csv -Header "USERNAME","SESSIONNAME","ID","STATE","IDLE_TIME","LOGON_TIME"
        #$FinalUserArray = $InitUserArray | Select-Object -Skip 1
        ##############\__________break__________/##############
        $FoundTermSvcUser = $FinalUserArray.USERNAME
        # Create new array matching user UPN syntax and found user from above query.exe 
        $MatchedRegUserArray = @()
        foreach ($RegUser in $RegUserSessions) {
            if ($RegUser -match "LoggedOnUser=.+\.[A-Za-z]+\\[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9]{1,63}\.){1,125}[A-Za-z]{2,63}" ) {
                if ($RegUser -match "$FoundTermSvcUser" ) {
                    $MatchedRegUserArray += $RegUser
                }
            }
        }
        $script:DownLevel_RegUserName = $MatchedRegUserArray.LoggedOnSAMUser | Get-Unique
        $script:DisplayName_RegUserName = $MatchedRegUserArray.LoggedOnDisplayName | Get-Unique
        # Ensure that $MatchedRegUserArray contains UPN format
        if (($MatchedRegUserArray.LoggedOnUser | Get-Unique) -match "$FoundTermSvcUser") {
            # Select UPN if contained within array $MatchedRegUserArray
            $script:UserUPN_RegUserName = ($MatchedRegUserArray.LoggedOnUser | Get-Unique).Split("\")[1]
            Write-Output "Successfully obtained UPN: `"$UserUPN_RegUserName`" from the registry. Moving on..."
        } elseif ((($MatchedRegUserArray.LoggedOnUser | Get-Unique) -notmatch "$FoundTermSvcUser") -and (Test-ComputerSecureChannel)) {
            # Obtain UPN from AD DS if connection to domain is available
            $script:ADUserAttributes = GetUserAttributes -name $FoundTermSvcUser
            $script:UserUPN_RegUserName = $ADUserAttributes.UserPrincipalName
            Write-Output "Setup could not obtain UPN from the registry so `"$UserUPN_RegUserName`" was pulled from AD DS instead. Moving on..."
            $script:IsADsourced = $true
        } else {
            # Format UPN manually as fallback
            Write-Output "Setup could not obtain UPN from the registry or AD DS as a fallback."
            Write-Output "This may be because there is no active connection to the directory. Will build UPN manually..."
            if (!($UserDC)) { $UserDC = (Get-WmiObject Win32_ComputerSystem).Domain }
            $UserCN = ($MatchedRegUserArray.LoggedOnSAMUser | Get-Unique).Split("\")[1]
            if ($UserCN -match $FoundTermSvcUser) {
                $script:UserUPN_RegUserName = $UserCN + "@" + $UserDC
            } else {
                $script:UserUPN_RegUserName = $FoundTermSvcUser + "@" + $UserDC
            }
            Write-Output "Constructed UPN: `"$UserUPN_RegUserName`" manually. If the matched domain is incorrect for the user,"
            Write-Output "you can declare the value of `"`$UserDC`" to override this. Continuing..."
        }
        Write-Output "Found user: `"$DisplayName_RegUserName`" with existing session in registry path:`n$UserSessionRegSource`nWill run installer as: $DownLevel_RegUserName"
    } else {
        $script:DownLevel_RegUserName = $RegUserNamesSAM
        $script:DisplayName_RegUserName = $RegUserSessions.LoggedOnDisplayName | Sort-Object | Get-Unique
        $script:UserUPN_RegUserName = ($RegUserSessions.LoggedOnUser | Get-Unique).Split("\")[1]
        Write-Output "Found single user `"$DisplayName_RegUserName`" from Registry path:`n$UserSessionRegSource`nWill run installer as: $DownLevel_RegUserName..."
    }
    $script:CN_RegUserName = $DownLevel_RegUserName.Split("\")[1]
    $script:logged_on_user = $DownLevel_RegUserName
    $script:IsSourcedfromREG = $true
}


# Backup user identification if script is run on a remote machine in which Get-WMIObject cannot define
# Will query AD for mssing user domain attributes
if (!$logged_on_user) {
    #$DownLevel_RegUserName = ""
    #$DisplayName_RegUserName = ""
    #$UserUPN_RegUserName = ""
    #$CN_RegUserName = ""
    $logged_on_user = ""
    $IsSourcedfromREG = ""
    Write-Output "User is remoted into this machine so verifying logged in user against registry session cache..."
    DiscoverLoggedonUser
}

#Retreive Intune UDID
#if (!($WIN_UDID)) {
#    $WinCheckUDID = wmic path win32_computersystemproduct get UUID
#    $WIN_UDID = $WinCheckUDID[2]
#}
#if (!($INTUNE_UDID)) {
#    $IntuneRegSource = "HKLM:\SOFTWARE\Microsoft\Enrollments\*\DMClient\MS DM Server"
#    $IntuneRegKey = Get-ChildItem -path $IntuneRegSource
#    $IntuneRegKey = $IntuneRegKey -replace "HKEY_LOCAL_MACHINE","HKLM:"
#    $IntuneDeviceInfo = Get-ItemProperty -Path $IntuneRegKey
#    $INTUNE_UDID = $IntuneDeviceInfo.EntDMID
#}

############################################################
################ End Custom ID User Part 1 #################
############################################################


Write-Host "Installing app for user: $logged_on_user"

$global_profile_dir = "C:\ProgramData"



$MY_USER = ""
$MY_EMAIL = ""
function get_user_email() {
    if (!$MULTI_USER) {
        # for a single user device, assumes you can get user and email because device is joined to an
        # Azure AD domain: https://nerdymishka.com/articles/azure-ad-domain-join-registry-keys/
        # (you may use other techniques here as well)

        ## Removing Intune Reg Key from script
        #$intune_info = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
        #if (!(Test-Path $intune_info)) {
        #    Write-Host "Extracting user email from: $intune_info"
        #    $ADJoinInfo = Get-ChildItem -path $intune_info
        #    $ADJoinInfo = $ADJoinInfo -replace "HKEY_LOCAL_MACHINE","HKLM:"
        #    $ADJoinUser = Get-ItemProperty -Path $ADJoinInfo
        #    $script:MY_EMAIL = $ADJoinUser.UserEmail
        #    $script:MY_USER = $MY_EMAIL.Split("@")[0]    
        #} elseif ($IsADsourced -eq $true) {
        
        if ($IsADsourced -eq $true) {
            # By default, the user's Mail attribute is selected for their CSE login email address.
            # You can comment that line and uncomment the following line such that the user's UPN
            # is selected for their CSE login email address
            Write-Output "Machine is not joined to Entra ID so sourcing user mail attribute from AD DS!`n"
            $script:MY_EMAIL = $ADUserAttributes.Mail
            #$script:MY_EMAIL = $ADUserAttributes.UserPrincipalName
            $script:MY_USER = $DisplayName_RegUserName
        } elseif (($IsSourcedfromREG -eq $true) -and (Test-ComputerSecureChannel)) {
            # Note that this block activates if user is remoted into their machine AND
            # if the Machine has a valid connection to AD DS. Attributes are pulled from
            # AD DS in case the user's mail attributes differ from their login UPN.
            # You may change this by swapping the $MY_EMAIL variable below
            Write-Output "Machine is not joined to Entra ID so sourcing user info from AD DS and registry session cache!`n"
            $ADUserAttributes = GetUserAttributes -name $CN_RegUserName
            $script:MY_EMAIL = $ADUserAttributes.Mail
            #$script:MY_EMAIL = $ADUserAttributes.UserPrincipalName
            $script:MY_USER = $DisplayName_RegUserName
        } else {
            # This code block will grab user attributes purely from the local registry
            # Note that this could cause innacuracies in some environments if the user's
            # mail attribute differs from their UPN attribute
            Write-Output "Machine is not Entra ID joined and does not have valid AD DS connection.`nPulling user attributes from localhost only!"
            DiscoverLoggedonUser
            $script:MY_USER = $DisplayName_RegUserName
            $script:MY_EMAIL = $UserUPN_RegUserName
        }
    }
    Write-Host "Installing for user with name: $MY_USER"
    Write-Host "Installing for user with email: $MY_EMAIL"
    if (!$MY_EMAIL) {
        Write-Host "No user specified - device certificate will be issued to the default **STAGED USER**"
    }
}
############################################################
#################### End Custom ID User ####################
############################################################
############## Original Banyan Function Below ##############
############################################################
#function get_user_email() {
#    if (!$MULTI_USER) {
#        # for a single user device, assumes you can get user and email because device is joined to an
#        # Azure AD domain: https://nerdymishka.com/articles/azure-ad-domain-join-registry-keys/
#        # (you may use other techniques here as well)
#        $intune_info = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
#        if (Test-Path $intune_info) {
#            Write-Host "Extracting user email from: $intune_info"
#            $ADJoinInfo = Get-ChildItem -path $intune_info
#            $ADJoinInfo = $ADJoinInfo -replace "HKEY_LOCAL_MACHINE","HKLM:"
#            $ADJoinUser = Get-ItemProperty -Path $ADJoinInfo
#            $script:MY_EMAIL = $ADJoinUser.UserEmail
#            $script:MY_USER = $MY_EMAIL.Split("@")[0]
#        }
#    }
#    Write-Host "Installing for user with name: $MY_USER"
#    Write-Host "Installing for user with email: $MY_EMAIL"
#    if (!$MY_EMAIL) {
#        Write-Host "No user specified - device certificate will be issued to the default **STAGED USER**"
#    }
#}

function create_config() {
    Write-Host "Creating mdm-config json file"

    $banyan_dir_name = "Banyan"
    $global_config_dir = $global_profile_dir + "\" + $banyan_dir_name
    $global_config_file = $global_config_dir + "\" + "mdm-config.json"


    # You may add the following optional params to $json object below
    # mdm_vendor_udid = $INTUNE_UDID
    $json = [pscustomobject]@{
        mdm_invite_code = $INVITE_CODE
        mdm_deploy_user = $MY_USER
        mdm_deploy_email = $MY_EMAIL
        mdm_device_ownership = $DEVICE_OWNERSHIP
        mdm_ca_certs_preinstalled = $CA_CERTS_PREINSTALLED
        mdm_skip_cert_suppression = $SKIP_CERT_SUPPRESSION
        mdm_present = $IS_MANAGED_DEVICE
        mdm_vendor_name = $DEVICE_MANAGER_NAME
        mdm_hide_services = $HIDE_SERVICES
        mdm_disable_quit = $DISABLE_QUIT
        mdm_start_at_boot = $START_AT_BOOT
        mdm_auto_login = $AUTO_LOGIN
        mdm_hide_on_start = $HIDE_ON_START
        mdm_disable_auto_update = $DISABLE_AUTO_UPDATE
        mdm_reporting_interval = $ENDPOINT_REPORT_INTERVAL
        mdm_login_token_prompt_time = $TOKEN_NOTIFY

    } | ConvertTo-Json

    New-Item -Path $global_profile_dir -Name $banyan_dir_name -ItemType "directory" -Force | Out-Null
    Set-Content -Path $global_config_file -Value $json -NoNewLine
}


function download_install() {
    Write-Host "Downloading installer EXE"

    $tmp_dir_name = "banyantemp"
    $tmp_dir = $global_profile_dir + "\" + $tmp_dir_name

    New-Item -Path $global_profile_dir -Name $tmp_dir_name -ItemType "directory" -Force | Out-Null

    $dl_file = $tmp_dir + "\" + "Banyan-Setup-$APP_VERSION.exe"

    $progressPreference = 'silentlyContinue'
    # NT WebClient is a much faster method to download files
    (New-Object Net.WebClient).DownloadFile("https://www.banyanops.com/app/releases/Banyan-Setup-$APP_VERSION.exe", $dl_file)
    # Fallback to classic Invoke-Webrequest - can probably remove this
    if ((Test-Path $dl_file) -eq $false) {
        Invoke-Webrequest "https://www.banyanops.com/app/releases/Banyan-Setup-$APP_VERSION.exe" -outfile $dl_file -UseBasicParsing
    } else {
        Write-Output "Downloaded Banyan app version $APP_VERSION to:`n$dl_file"
    }
    $progressPreference = 'Continue'

    Write-Host "Run installer"
    Start-Process -FilePath $dl_file -ArgumentList "/S" -Wait
    Start-Sleep -Seconds 3
}


function stage() {
    Write-Host "Running staged deployment"
    $process = Start-Process -FilePath "C:\Program Files\Banyan\resources\bin\banyanapp-admin.exe" -ArgumentList "stage --key=$DEPLOYMENT_KEY" -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        Write-Host "Error during staged deployment"
        exit 1
    }
    Start-Sleep -Seconds 3
    Write-Host "Staged deployment done. Have the logged_on_user start the Banyan app to complete registration."
}


function create_scheduled_task($task_name) {
    Write-Host "Creating ScheduledTask $task_name for logged_on_user, so app launches upon next user login"
    $action = New-ScheduledTaskAction -Execute "C:\Program Files\Banyan\Banyan.exe"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $logged_on_user
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal
    Register-ScheduledTask $task_name -InputObject $task
}

function delete_scheduled_task($task_name) {
    Write-Host "Deleting ScheduledTask $task_name"
    Unregister-ScheduledTask -TaskName $task_name -Confirm:$false
}

# since Windows doesn't have "su - username", we use scheduled_task to launch Banyan app as logged_on user
function start_app() {
    Write-Host "Running ScheduledTask to start the Banyan app as: $logged_on_user"
    $task_name = "StartBanyanTemp"
    create_scheduled_task($task_name)
    Start-ScheduledTask -TaskName $task_name
    Start-Sleep -Seconds 5
    delete_scheduled_task($task_name)
}

function allow_app() {
    if ($ALLOW_APP) {
        New-NetFirewallRule `
            -DisplayName "SonicWall-CSE-App" `
            -Program "C:\Program Files\Banyan\Banyan.exe" `
            -Direction Outbound `
            -Action Allow `
            -Profile Public,Private,Domain
        }
}

function stop_app() {
    Write-Host "Stopping Banyan app"
    Get-Process -Name Banyan -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
}


if (($INVITE_CODE -eq "upgrade") -and ($DEPLOYMENT_KEY -eq "upgrade")) {
    Write-Host "Running upgrade flow"
    stop_app
    download_install
    start_app
} else {
    Write-Host "Running zero-touch install flow"
    stop_app
    get_user_email
    create_config
    download_install
    stage
    create_config
    allow_app
    start_app
}
