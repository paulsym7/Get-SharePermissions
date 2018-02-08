Function Get-SharePermissions {
<#
.Synopsis
   This function will discover which security groups contain other groups as members and output a list of these groups.
.DESCRIPTION
   This function will discover which security groups contain other groups as members and output a list of these groups. Any security groups found as members will in turn be searched to check if they have any security groups as members.
   By default this function will output a list of nested groups found, use the -DisplayParent parameter switch to output a hash table of nested groups and their parent group.
.EXAMPLE
   Get-NestedGroup -GroupName SecurityGroup1

   This command will output a list of all nested groups found as members of SecurityGroup1
.EXAMPLE
   Get-SharePermissions -GroupName SecurityGroup1 -DisplayParent

   This command will output a list of all nested groups found as members of SecurityGroup1 and list the security group it is nested within
#>
    [CmdletBinding()]
    Param(
        # Name of the share to evaluate
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]$ShareName,

        # Param2 help description
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Server = $env:COMPUTERNAME,

        [switch]$IncludeDefaultShares,

        [switch]$DisplayParent
        )

    BEGIN {
        $DefaultShares = New-Object System.Collections.ArrayList
        $DefaultShares.Add('Admin$') | Out-Null
        (Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $Server).DeviceID.Replace(':','$') | foreach {$DefaultShares.Add($_)} | Out-Null

        # Build share paths
        $shares = New-Object System.Collections.ArrayList
        If($IncludeDefaultShares){
            foreach($defshare in $DefaultShares){
                $shares.Add('\\' + $Server + '\' + $defshare) | Out-Null
            }
        }
        foreach($share in $ShareName){
            Write-Verbose "Found $share share"
            $Shares += '\\' + $Server + '\' + $share
        }
    }

    PROCESS {
        foreach($fileshare in $shares){
            Write-Verbose "Evaluating the $fileshare share"
            $NTFSPermissions = (Get-Acl -Path $fileshare).Access
            $ShareOwner = (Get-Acl -Path $fileshare).Owner
            $fs = $fileshare.Split('\')[3]
            If($Server -eq $env:COMPUTERNAME){
                $SharePermissions = Get-SmbShareAccess -Name $fs
            }
            Else{
                Write-Verbose "Checking the $fs share"
                $SharePermissions = Invoke-Command -ScriptBlock {Get-SmbShareAccess -Name $using:fs} -ComputerName $Server
            }

            # Build array of users that have permissions to the share
            $DomainGroups = $NTFSPermissions.Where{$_.IdentityReference -like "$env:USERDOMAIN\*"}.IdentityReference
            $Builtin = $NTFSPermissions.Where{$_.IdentityReference -like 'BUILTIN\*'}.IdentityReference
            $Users = New-Object System.Collections.ArrayList
            $GroupInfo = New-Object System.Collections.ArrayList
            foreach($group in $DomainGroups){
                try{
                    $UserPermission = Get-ADGroupMember -Identity $group.Value.Split('\')[1] -Recursive -ErrorAction Stop
                    Write-Verbose "Evaluating the $($group.Value.Split('\')[1]) identity reference"
                    foreach($user in $UserPermission){
                        $Users.Add($User.SamAccountName) | Out-Null
                    }
                    If($DisplayParent){
                        Write-Verbose "Calling the Get-NestedGroup function with the -Groupname $($group.Value.Split('\')[1]) parameter"
                        $nested = Get-NestedGroup -GroupName $group.Value.Split('\')[1] -DisplayParent -Verbose
                    }
                    Else{
                        $nested = Get-NestedGroup -GroupName $group.Value.Split('\')[1] -Verbose
                    }
                    $GroupInfo.Add(@{GroupName = $group.Value.Split('\')[1]
                                     NestedGroups = $Nested}) | Out-Null
                }
                catch{
                    $UserPermission = Get-ADUser -Identity $group.Value.Split('\')[1]
                    $Users.Add($UserPermission.SamAccountName) | Out-Null
                }
            }

            # Build hash table of users and their group memberships
            $UserGroups = New-Object System.Collections.ArrayList
            foreach($User in ($Users | select -Unique)){
                Write-Verbose "Checking group membership of $user"
                $groups = (Get-ADUser -Identity $user -Properties MemberOf).MemberOf
                $MemberOf = New-Object System.Collections.ArrayList
                foreach($group in $groups){
                    $GroupDetail = Get-ADGroup -Identity $group -Properties MemberOf
                    If($GroupDetail.MemberOf){
                        for($i = 0; $i -lt $GroupDetail.MemberOf.Count; $i++){
                            $MemberOf.Add($GroupDetail.MemberOf[$i].Split(',')[0].Replace('CN=','')) | Out-Null
                        }
                    }
                    Else{
                        $MemberOf.Add($GroupDetail.Name) | Out-Null
                    }
                }
                $UserGroups.Add(@{User = $User
                                  Groups = $MemberOf}) | Out-Null
            }
            
            # Compare each users group membership with the sharepermission
            $NTFS = New-Object System.Collections.ArrayList
            foreach($identityreference in $DomainGroups){
                $SecurityPrinciple = $identityreference.value.Split('\')[1]
                try{
                    Get-ADGroup -Identity $SecurityPrinciple -ErrorAction Stop | Out-Null
                    $NTFS.Add(@{Identity = $SecurityPrinciple
                                AccessControlType = ($NTFSPermissions.Where{$_.IdentityReference -like "*$SecurityPrinciple"}).AccessControlType
                                FileSystemRights = ($NTFSPermissions.Where{$_.IdentityReference -like "*$SecurityPrinciple"}).FileSystemRights
                                NestedGroups = (($GroupInfo.Where{$_.GroupName -like "*$SecurityPrinciple"}).NestedGroups | select -Unique)
                                PermissionsAssigned = 'From group membership'
                                Users = ($UserGroups.where{$_.groups -eq $SecurityPrinciple}).User}) | Out-Null
                }
                catch{
                    # It is a user account with explicitly assigned permissions
                    $NTFS.Add(@{Identity = $SecurityPrinciple
                                AccessControlType = ($NTFSPermissions.Where{$_.IdentityReference -like "*$SecurityPrinciple"}).AccessControlType
                                FileSystemRights = ($NTFSPermissions.Where{$_.IdentityReference -like "*$SecurityPrinciple"}).FileSystemRights
                                NestedGroups = ''
                                PermissionsAssigned = 'Directly'
                                Users = $SecurityPrinciple}) | Out-Null
                }
            }
            If($Builtin){
                foreach($group in ($Builtin | select -Unique)){
                    Write-Verbose "Checking the $group permissions"
                    $NTFS.Add(@{Identity = $group.Value
                                AccessControlType = (($NTFSPermissions.Where{$_.IdentityReference -eq $group}).AccessControlType | select -Unique)
                                PermissionsAssigned = 'Group'
                                NestedGroups = ''
                                FileSystemRights = ($NTFSPermissions.Where{$_.IdentityReference -eq $group}).FileSystemRights}) | Out-Null
                }
            }

            $SharePerms = New-Object System.Collections.ArrayList
            foreach($account in $SharePermissions){
                Write-Verbose "Checking $($account.AccountName) share permissions"
                $SharePerms.Add(@{Identity = $account.AccountName
                                  AccessControlType = $account.AccessControlType
                                  AccessRight = $account.AccessRight}) | Out-Null
            }

            [PSCustomObject]@{ShareName = $fileshare
                              Owner = $ShareOwner
                              NTFS = $NTFS
                              Share = $SharePerms}
        } #foreach
    }

    END {}
}
