##############################################################################################
#
# Group Copy Script 1.1 by Nick Derrickson
# Created September 2015 for the College of Business Information Services Dept. in Austin 244
# Property of Oregon State University 
#
# Functions GetUserNamefromDUN and GetDomainfromDUN were created by Cary Shufelt
#
##############################################################################################

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}
# Checks to see if Powershell is running as Administrator, and if it isn't then it runs the process as Administrator.

Import-module ActiveDirectory
# Import all users and groups from AD

Function Get-FileName($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

Write-Host "Press enter to select the log file: "
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
$initialFile = "path omitted for security purposes"
$DatabaseFile = Get-FileName $initialFile
Write-Host "You have selected `"$DatabaseFile`" as your filepath for the CSV file.`n"
# Sets location of the file used to log information in this script.

function GetUserNamefromDUN ($DUN) {#gets username from "Domain\username" string
      [string]$DUN = $DUN
      $split = $DUN.split('\')
      $user = $split[1]
      return $user
}
# Parses the domain\username for the username

function GetDomainfromDUN ($DUN){
      [string]$DUN = $DUN
      $split = $DUN.split('\')
      $domain = $split[0]
      return $domain
}
# Parses the domain\username for the domain

DO
{
    $Source_DUN = Read-Host "Please enter the domain\username of the SOURCE user (EX: bus\john.smith or onid\smithj)"
    $Source_sAM = GetUsernamefromDUN $Source_DUN   # Gets the Source sAMAccountName from domain\username
    $Source_Domain = GetDomainfromDUN $Source_DUN   # Gets the Source Domain from domain\username
    $Source_User_Found = $false
    $Source_Server = "$Source_Domain.oregonstate.edu"   # Sets the fully-qualified domain name given the Source domain

    $User = Get-ADUser -Server $Source_Server -Filter {sAMAccountName -eq $Source_sAM}
    If ($User -eq $Null) 
    {
        Write-Host "User with sAMAccountName: `"$Source_sAM`" does not exist in domain `"$Source_Domain`"."
    }
    Else 
    {
        Write-Host "User with sAMAccountName: `"$Source_sAM`" found in domain "$Source_Domain".`n"
        $Source_User_Found = $true
    }
}
WHILE ($Source_User_Found -eq $false)
# Specifies the Source sAMAccountname and domain and verifies that it is an object in Active Directory.

DO
{
    $Target_DUN = Read-Host "Please enter the domain\username of the TARGET user (EX: bus\john.smith or onid\smithj)"
    $Target_sAM = GetUsernamefromDUN $Target_DUN   # Gets the Target sAMAccountName from domain\username
    $Target_Domain = GetDomainfromDUN $Target_DUN   # Gets the Target Domain from domain\username
    $Target_User_Found = $false
    $Target_Server = "$Target_Domain.oregonstate.edu"   # Sets the fully-qualified domain name given the Target domain

    $User = Get-ADUser -Server $Target_Server -Filter {sAMAccountName -eq $Target_sAM}
    If ($User -eq $Null) 
    {
        Write-Host "User with sAMAccountName: `"$Target_sAM`" does not exist in domain `"$Target_Domain`"."
    }
    Else 
    {
        Write-Host "User with sAMAccountName: `"$Target_sAM`" found in domain "$Target_Domain".`n"
        $Target_User_Found = $true
    }
}
WHILE ($Target_User_Found -eq $false)
# Specifies the Target sAMAccountname and domain and verifies that it is an object in Active Directory.

Write-Host "SOURCE User/Domain: $Source_sAM : $Source_Server"
Write-Host "TARGET User/Domain: $Target_sAM : $Target_Server"
# Repeats the Source and Target UPN/Servers back to the user.

$UserGroups = Get-ADUser -Identity $Source_sAM -Properties memberOf -Server $Source_Server | Select-Object -ExpandProperty memberOf
# Gets the groups that the Source user is a part of and store them in a variable.

$Group_Array = [Array]($UserGroups)   # Creates an array containing the groups of the Source user.
$Target_DN = Get-ADUser -Identity $Target_sAM -Server $Target_Server   # Gets the DN of the Target user.
$Num_Of_Groups = $Group_Array.count   # Counts the number of groups to be added.
$Status_Array = @("FAILURE") * $Num_Of_Groups   # Creates an array to log the status of each group add.
$Array = @(0) * $Num_Of_Groups   # Creates an array to log the status of all group adds.

$Num_Of_Groups_Added = 0   # Starts the group add count at 0.

$GroupMemberError = "Exception calling `"Add`" with `"1`" argument(s): `"The object already exists. (Exception from HRESULT: 0x80071392)`""
# Hardcodes the exception message that occurs when a user is already a member of a group.

$GroupScopeError = "Exception calling `"Add`" with `"1`" argument(s): `"The server is unwilling to process the request. (Exception from HRESULT: 0x80072035)`""
# Hardcodes the exception message that occurs when a group cannot be added due to the Group Scope.

If ($Num_Of_Groups -gt 0) 
{
    Write-Host "($Num_Of_Groups) Groups to be added to User ${Target_UPN}: "
    $UserGroups | Get-ADGroup | select Name | sort Name 
    Write-Host "----`n"
    # Displays the groups to be added.
    
    $Choice = ""
    while ($Choice -notmatch "[y|n]"){
        $Choice = read-host "Are you sure that you want to continue with the group copy process? (Y/N)"
    }
    
    If ($Choice -eq "y")
    {
        for ($i = 0; $i -lt $Num_Of_Groups; $i++)   # Goes through the array of groups and attempts to add each one to the Target user. 
        {
            Try 
            {
                $Group = $Group_Array[$i]
                $GroupName = $Group -replace "(CN=)(.*?),.*",'$2'
                Write-Host "`nAttempting to add user `"$Target_sAM`" to group `"$GroupName`"."
                # Specifies the group to be added and displays the Canonical name of the group to be added.

                $GroupLDAP = [ADSI]"LDAP://$Group"
                $DN = $Target_DN.distinguishedName
                Write-Host $DN
                $LDAPDN = "LDAP://$DN"
                # Specifies the full LDAP address of the group to be added.

	            $GroupLDAP.Add($LDAPDN)
                Write-Host "Successfully added user `"$Target_sAM`" to group `"$GroupName`"."
                $Num_Of_Groups_Added++
                $Status_Array[$i] = "SUCCESS"
                # Attempts to add the group to the Target user.
            }

            Catch   # If there is a failure during the group add process, then it will handle the error and attempt the next group.
            {
                If ($_.Exception.Message -eq $GroupMemberError)
                {
                    Write-Host "User `"$Target_sAM`" is already a member of `"$GroupName`""
                    # Shows that the Target user is already a part of the specified group.
                }

                Elseif ($_.Exception.Message -eq $GroupScopeError)
                {
                    Write-Host "`nGroup Scope of `"$GroupName`" does not allow for cross-domain copying of groups. 
In order to add this group to the Target user, the group scope needs to be `"Universal`" instead of `"Global`" or `"Domain Local`"."
                    # Shows that the specified Group is not a Universal group, so it can't be added cross-domain.
                }

                Else 
                {
                    $Error_Message = $_.Exception.Message
                    Write-Host "`nError occured. Error was: $Error_Message"
                    # Handles any errors that aren't errors relating to the user already being a part of the group or the group not being a Universal Group.
                }
            }
        }

        $Num_Of_Groups_Failed = $Num_Of_Groups - $Num_Of_Groups_Added
        Write-Host "`n($Num_Of_Groups_Added) Groups have been successfully added to $Target_sAM."
        # Counts the number of groups that were successfully added to the Target User

        If (!$Error)
        {
            "`nNo errors occured. Please verify that all groups have been added to the Target User.`n"
            $Error_Message = "No errors occured."
            # Shows that it ran error-free.
        }

        Else
        {
            Write-Host "`nError(s) occured. ($Num_Of_Groups_Failed) groups may not have been added to the Target user.`n"
            $Error_Message = "Error(s) occured. $Error_Message"
            # Collects and displays the error message.
        }

        for ($i = 0; $i -lt $Num_Of_Groups; $i++)
        {
            $Group = $Group_Array[$i]
            $GroupName = $Group -replace "(CN=)(.*?),.*",'$2'
            $Status = $Status_Array[$i]
            $Array[$i] = "`"$Status adding: $Group`""
            Write-Host $Array[$i]
            # Displays and logs status of each group add.
        } 

        $Break = "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" 
        $Break | Out-File $DatabaseFile -Encoding ascii -Append   # Creates a break in the log file to sep

        $Time = Get-date
        # Sets time for log collection

        $DatabaseContents = "$Time,$Source_sAM,$Source_Server,$Target_sAM,$Target_Server,$Error_Message"
        $col1 = $Time
        $col2 = $Source_sAM
        $col3 = $Source_Server
        $col4 = $Target_sAM
        $col5 = $Target_Server
        $col6 = $Error_Message
        $DatabaseContents | Out-File -filepath $DatabaseFile -NoClobber -Encoding ascii -Append
        # Outputs General Information about the time, users, servers, and errors to a CSV File.

        $Array | Out-File -filepath $DatabaseFile -NoClobber -Encoding ascii -Append
        # Outputs information about each group that was added and the status of each of them to a CSV file.
    }

    Else
    {
        Write-Host "`nGroup Copy process cancelled by user."
        # Displays a message when the copy is cancelled by the user.
    }
}

Else
{
    Write-Host "Source User is not a member of any groups. This could occur if a new user was accidentally specified as the Source User instead of the Target User."
    # Displays a message when a user without any group memberships is used as the Source user.
}

Write-Host -NoNewLine "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
# Exits the program