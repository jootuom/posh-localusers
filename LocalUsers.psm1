<#
Module for local user management.

For information about userFlags see:
http://msdn.microsoft.com/en-us/library/aa772300(VS.85).aspx

Formatting file:
http://msdn.microsoft.com/en-us/library/windows/desktop/dd878339(v=vs.85).aspx
#>

# TODO: Maybe use more unique object names?
# Do not try to add formatdata if it already exists, only update. (Causes an exception)
if (!(Get-FormatData "Local*")) {
	Update-FormatData -Append (Join-Path $PSScriptRoot LocalUsers.format.ps1xml)
}
else {
	Update-FormatData
}

Function Get-LocalUser {
	<#
	.SYNOPSIS
	Get a local user account
	.DESCRIPTION
	Gets and displays a local user account object
	.EXAMPLE
	Get-LocalUser "Administrator"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Name
	Name of account to retrieve. If omitted, get all local accounts.
	#>
	[CmdletBinding(

	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Position=0, ValueFromPipeline=$true)]
		[string] $Name = ""
	)
	begin {
		$users = @()
	}
	process {
		if ($Name) {
			Write-Verbose "User defined, retrieving specific user"
			Write-Verbose "User: $Name"
			
			$adsi = [ADSI]"WinNT://$Computer/$Name,user"
			
			$users += $adsi
		}
	}
	end {
		if (!$users) {
			Write-Verbose "User not defined, retrieving all users"
			
			$adsi = [ADSI]"WinNT://$Computer"
			
			$users += $adsi.psbase.children | where {
				$_.psbase.schemaClassName -match "user"
			}
		}
		
		# Change typenames so we can apply special formatting
		$users | foreach {
			$_.PSTypeNames.Insert(0, "LocalUser")
			
			$_
		}
	}
}

Function Get-LocalGroup {
	<#
	.SYNOPSIS
	Get a local group
	.DESCRIPTION
	Gets and displays a local group object
	.EXAMPLE
	Get-LocalGroup "Administrators"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Name
	Name of group to retrieve. If omitted, get all local groups.
	#>
	[CmdletBinding(

	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Position=0, ValueFromPipeline=$true)]
		[string] $Name
	)
	begin {
		$groups = @()
	}
	process {
		if ($Name) {
			Write-Verbose "Group defined, retrieving specific group"
			Write-Verbose "Group: $Name"
			
			$adsi = [ADSI]"WinNT://$Computer/$Name,group"
			
			$groups += $adsi
		}
	}
	end {
		if (!$groups) {
			Write-Verbose "Group not defined, retrieving all groups"
			
			$adsi = [ADSI]"WinNT://$Computer"
			
			$groups += $adsi.psbase.children | where {
				$_.psbase.schemaClassName -match "group"
			}
		}
		
		# Change typenames so we can apply special formatting
		$groups | foreach {
			$_.PSTypeNames.Insert(0, "LocalGroup")
			
			$_
		}
	}
}

Function Get-LocalGroupMember {
	<#
	.SYNOPSIS
	Get members of a local group
	.DESCRIPTION
	Gets and displays all members of a local group
	.EXAMPLE
	Get-LocalGroupMember "Administrators"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Name
	Name of group to retrieve. If omitted, get members of all local groups.
	#>
	[CmdletBinding(

	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Position=0, ValueFromPipeline=$true)]
		[string] $Name = ""
	)
	begin {
		$groups = @()
	}
	process {
		if ($Name) {
			Write-Verbose "Group defined, retrieving specific group"
			Write-Verbose "Group: $Name"
			
			$adsi = [ADSI]"WinNT://$Computer/$Name,group"
			
			$groups += $adsi
		}
	}
	end {
		if (!$groups) {
			Write-Verbose "Group not defined, retrieving all groups"
			
			$adsi = [ADSI]"WinNT://$Computer"
		
			$groups += $adsi.psbase.children | where {
				$_.psbase.schemaClassName -match "group"
			}
		}
		
		foreach ($group in $groups) {
			Write-Verbose "Enumerating group: $($group.Name)"
			
			$group.Members() | foreach {
				$groupobj = New-Object PSObject -Property @{
					GroupName   = $group.Name[0];
					Name        = "";
					FullName    = "";
					Description = "";
				}
			
				$groupobj.Name = $_.GetType().InvokeMember(
					"Name", "GetProperty", 	$null, $_, $null
				)
				
				# Ruins output
				#Write-Verbose "Found member: $($groupobj.Name)"
				
				# Some built-in objects don't have these properties
				try {
					$groupobj.FullName    = $_.GetType().InvokeMember(
						"FullName", "GetProperty", $null, $_, $null
					)
					
					$groupobj.Description = $_.GetType().InvokeMember(
						"Description", "GetProperty", $null, $_, $null
					)
				} 
				catch {
					# pass
				}
				
				$groupobj.PSTypeNames.Insert(0, "LocalGroupMemberData")
				
				$groupobj
			}
		}
	}
}

Function Set-LocalUser {
	<#
	.SYNOPSIS
	Set parameters of a local user account
	.DESCRIPTION
	Set parameters of a local user account
	.EXAMPLE
	Set-LocalUser Administrator -Description "Administrator account" -NeverExpirePwd
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Name
	Name of account to modify
	.PARAMETER Description
	Set user's description
	.PARAMETER FullName
	Set user's full name
	.PARAMETER CantChangePwd
	User cannot change password, toggle
	.PARAMETER MustChangePwd
	User must change password (on login), toggle
	.PARAMETER NeverExpirePwd
	User's password will never expire, toggle
	.PARAMETER LoginScript
	Set user's login script
	
	To clear this once set, use the value "`0".
	.PARAMETER Profile
	Set user's profile path
	
	To clear this once set, use the value "`0".
	.PARAMETER HomeDirDrive
	Drive letter for user's homedir
	
	i.e. "E:"
	Leave empty for local HomeDirectory
	.PARAMETER HomeDirectory
	Location for user's home directory
	
	If HomeDirDrive is set, this needs to be an UNC path.
	To clear this once set, use the value "`0" for HomeDirDrive and HomeDirectory.
	#>
	<#
	TODO: Is it possible to set/clear Locked out?
	It's possible to hack that by setting the userFlags to 512 but it
	removes everything else.
	#>
	[CmdletBinding(
		DefaultParameterSetName="Normal",
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Position=0, ValueFromPipeline=$true)]
		[string] $Name = "",
		
		[Parameter()]
		[string] $Description = "",
		
		[Parameter()]
		[string] $FullName = "",
		
		[Parameter(ParameterSetName="Normal")]
		[switch] $CantChangePwd,
		
		[Parameter(ParameterSetName="MustChangePwd")]
		[switch] $MustChangePwd,
		
		[Parameter(ParameterSetName="Normal")]
		[switch] $NeverExpirePwd,
		
		[Parameter()]
		[string] $LoginScript = "",
		
		[Parameter()]
		[string] $Profile = "",
		
		[Parameter(ParameterSetName="Homedir")]
		[string] $HomeDirDrive = "",
		
		[Parameter(ParameterSetName="Homedir", Mandatory=$true)]
		[string] $HomeDirectory = ""
		
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($Name)) {
			$adsi = [ADSI]"WinNT://$Computer/$Name,user"
			
			if ($Description) {
				$adsi.Description = $Description
			}
			
			if ($FullName) {
				$adsi.FullName = $FullName
			}
			
			if ($CantChangePwd) {
				$adsi.userFlags = ($adsi.userFlags[0] -BXOR 64)
			}
			
			if ($MustChangePwd) {
				if ($adsi.PasswordExpired[0] -eq 0) {
					$adsi.PasswordAge = 0
					$adsi.PasswordExpired = 1
				}
				else {
					$adsi.PasswordExpired = 0
				}
			}
			
			if ($NeverExpirePwd) {
				$adsi.userFlags = ($adsi.userFlags[0] -BXOR 65536)
			}
			
			if ($LoginScript) {
				$adsi.LoginScript = $LoginScript
			}
			
			if ($Profile) {
				$adsi.Profile = $Profile
			}
			
			if ($HomeDirectory) {
				$adsi.HomeDirDrive = $HomeDirDrive
				$adsi.HomeDirectory = $HomeDirectory
			}
			
			$adsi.SetInfo()
		}
	}
	end {

	}
}

Function Set-LocalGroup {
	<#
	.SYNOPSIS
	Set parameters of a local group
	.DESCRIPTION
	Set parameters of a local group
	.EXAMPLE
	Set-LocalGroup "Administrators" -Description "Administrators for this computer"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Description
	Set group's description
	#>
	[CmdletBinding(

	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Position=0, ValueFromPipeline=$true)]
		[string] $Name = "",
		
		[Parameter()]
		[string] $Description = ""
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($Name)) {
			$adsi = [ADSI]"WinNT://$Computer/$Name,group"
			
			if ($Description) {
				$adsi.Description = $Description
			}
			
			$adsi.SetInfo()
		}
	}
	end {

	}
}

Function Rename-LocalObject {
	<#
	.SYNOPSIS
	Rename a local user or group
	.DESCRIPTION
	Rename a local user or group
	.EXAMPLE
	Rename-LocalObject "Administrators" "Admins"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Name
	Name of object to rename
	.PARAMETER NewName
	New name for object
	#>
	[CmdletBinding(

	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Position=0, ValueFromPipeline=$true)]
		[string] $Name = "",
		
		[Parameter(Mandatory=$true)]
		[string] $NewName
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($Name)) {
			Write-Verbose "Renaming $Name to $NewName"
		
			$adsi = [ADSI]"WinNT://$Computer/$Name"
			
			$adsi.Rename($NewName)
		}
	}
	end {

	}
}

Function Search-LocalObject {
	<#
	.SYNOPSIS
	Search for and return a local object's path
	.DESCRIPTION
	Search for and return a local object's path
	.EXAMPLE
	Search-LocalObject "Administrator"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Name
	Name of account to search for
	#>
	[CmdletBinding(

	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Position=0)]
		[string] $Name = ""
	)
	begin {

	}
	process {
		$adsi = [ADSI]"WinNT://$Computer"
		
		# TODO: return a nicer object?
		return (
			$adsi.psbase.children |
			where {
				($_.psbase.schemaClassName -match "user" -or 
				$_.psbase.schemaClassName -match "group") -and 
				$_.psbase.name -eq $Name
			}
		).Path
	}
	end {

	}
}
 
Function New-LocalUser {
	<#
	.SYNOPSIS
	Create a new local user
	.DESCRIPTION
	Create a new local user
	.EXAMPLE Name
	New-LocalUser "MyUser"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Name
	Name of new user
	.PARAMETER FullName
	Set user's full name
	.PARAMETER Description
	Set user's description
	.PARAMETER Password
	Set user's password
	if omitted, Must Change Password will be on and the password will be blank.
	#>
	[CmdletBinding(
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
		[string] $Name,
		
		[Parameter()]
		[string] $FullName = "",
		
		[Parameter()]
		[string] $Description = "",
		
		[Parameter()]
		[string] $Password
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($Name)) {
			$adsi = [ADSI]"WinNT://$Computer"
			
			$user = $adsi.Create("User", $Name)
			
			$user.SetInfo()
			
			$user.FullName = $FullName
			
			$user.Description = $Description
			
			if ($Password) {
				$user.setpassword($Password)
			}
			
			$user.SetInfo()
		}
	}
	end {

	}
}

Function New-LocalGroup {
	<#
	.SYNOPSIS
	Create a new local group
	.DESCRIPTION
	Create a new local group
	.EXAMPLE
	New-LocalGroup "MyGroup"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Name
	Name of new group
	.PARAMETER Description
	Set group's description
	#>
	[CmdletBinding(
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
		[string] $Name,
		
		[Parameter()]
		[string] $Description = ""
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($Name)) {
			$adsi = [ADSI]"WinNT://$Computer"
			
			$group = $adsi.Create("Group", $Name)
			
			$group.SetInfo()
			
			$group.Description = $Description
			
			$group.SetInfo()
		}
	}
	end {

	}
}

Function Remove-LocalUser {
	<#
	.SYNOPSIS
	Remove a local user
	.DESCRIPTION
	Remove a local user
	.EXAMPLE
	Remove-LocalUser "MyUser"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Name
	Name of user to remove
	#>
	[CmdletBinding(
		SupportsShouldProcess=$true,
		ConfirmImpact="High"
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
		[string] $Name
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($Name)) {
			$adsi = [ADSI]"WinNT://$Computer"
			
			$adsi.Delete("User", $Name)
		}
	}
	end {

	}
}

Function Remove-LocalGroup {
	<#
	.SYNOPSIS
	Remove a local group
	.DESCRIPTION
	Remove a local group
	.EXAMPLE
	Remove-LocalGroup "MyGroup"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER GroupName
	Name of group to remove
	#>
	[CmdletBinding(
		SupportsShouldProcess=$true,
		ConfirmImpact="High"
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
		[string] $GroupName
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($GroupName)) {
			$adsi = [ADSI]"WinNT://$Computer"
			
			$adsi.Delete("Group", $GroupName)
		}
	}
	end {

	}
}

Function Add-LocalGroupMember {
	<#
	.SYNOPSIS
	Add member to a local group
	.DESCRIPTION
	Add member to a local group
	.EXAMPLE
	Add-LocalGroupMember "Administrators" "MyUser"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER GroupName
	Name of group to add a member to
	.PARAMETER Member
	Name of member to add
	.PARAMETER LocalUser
	User is a local user
	
	default.
	.PARAMETER DomainUser
	User is a domain user
	#>
	[CmdletBinding(
		DefaultParameterSetName="LocalUser",
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"	
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Mandatory=$true, Position=0)]
		[string] $GroupName,
		
		[Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
		[string] $Member,
		
		[Parameter(ParameterSetName="LocalUser")]
		[switch] $LocalUser,
		
		[Parameter(ParameterSetName="DomainUser")]
		[switch] $DomainUser
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($GroupName)) {
			Write-Verbose "Adding $Member to $GroupName"
		
			$adsi = [ADSI]"WinNT://$Computer/$GroupName,group"
			
			if ($PSCmdlet.ParameterSetName -eq "LocalUser") {
				$adsi.add("WinNT://$Computer/$Member,user")
			}
			else {
				# FIXME: Can domain != this?
				$adsi.add("WinNT://$env:userdnsdomain/$Member,user")
			}
		}
	}
	end {

	}
}

Function Remove-LocalGroupMember {
	<#
	.SYNOPSIS
	Remove member from a group
	.DESCRIPTION
	Remove member from a group
	.EXAMPLE
	Remove-LocalGroupMember "Administrators" "MyUser"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER GroupName
	Name of group to remove from
	.PARAMETER Member
	Name of member to remove
	.PARAMETER LocalUser
	User is a local user
	
	default.
	.PARAMETER DomainUser
	User is a domain user
	#>
	[CmdletBinding(
		DefaultParameterSetName="LocalUser",
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Mandatory=$true, Position=0)]
		[string] $GroupName,
		
		[Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
		[string] $Member,
		
		[Parameter(ParameterSetName="LocalUser")]
		[switch] $LocalUser,
		
		[Parameter(ParameterSetName="DomainUser")]
		[switch] $DomainUser
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($GroupName)) {
			Write-Verbose "Removing $Member from $GroupName"
		
			$adsi = [ADSI]"WinNT://$Computer/$GroupName,group"
		
			if ($PSCmdlet.ParameterSetName -eq "LocalUser") {
				$adsi.remove("WinNT://$Computer/$Member,user")
			}
			else {
				# FIXME: Can domain != this?
				$adsi.remove("WinNT://$env:userdnsdomain/$Member,user")
			}
		}
	}
	end {

	}
}

Function Reset-LocalAccountPassword {
	<#
	.SYNOPSIS
	Reset password of local account
	.DESCRIPTION
	Reset password of local account
	.EXAMPLE
	Reset-LocalAccountPassword "Administrator"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Account
	Target account
	.PARAMETER Password
	New password
	#>
	[CmdletBinding(
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Mandatory=$true, Position=0)]
		[string] $Account,
		
		[Parameter(Position=1)]
		[string] $Password = ""
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($Account)) {
			$adsi = [ADSI]"WinNT://$Computer/$Account,user"
			
			$adsi.setpassword($Password)
			
			$adsi.setInfo()
		}
	}
	end {

	}
}

Function Enable-LocalAccount {
	<#
	.SYNOPSIS
	Enable a local account
	.DESCRIPTION
	Enable a local account
	.EXAMPLE
	Enable-LocalAccount "Administrator"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Account
	Target account
	#>
	[CmdletBinding(
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Mandatory=$true, Position=0)]
		[string] $Account
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($Account)) {
			$adsi = [ADSI]"WinNT://$Computer/$Account,user"
			
			if ($adsi.UserFlags[0] -BAND 2) {
				$adsi.userFlags = ($adsi.userFlags[0] -BXOR 2)
				
				$adsi.SetInfo()
			}
		}
	}
	end {

	}
}

Function Disable-LocalAccount {
	<#
	.SYNOPSIS
	Disable a local account
	.DESCRIPTION
	Disable a local account
	.EXAMPLE
	Disable-LocalAccount "Administrator"
	.PARAMETER Computer
	Target computer
	
	default: current computer
	.PARAMETER Account
	Target account
	#>
	[CmdletBinding(
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter()]
		[string] $Computer = $env:ComputerName,
		
		[Parameter(Mandatory=$true, Position=0)]
		[string] $Account
	)
	begin {

	}
	process {
		if ($PSCmdlet.ShouldProcess($Account)) {
			$adsi = [ADSI]"WinNT://$Computer/$Account,user"
			
			if (!($adsi.UserFlags[0] -BAND 2)) {
				$adsi.userFlags = ($adsi.userFlags[0] -BOR 2)
				
				$adsi.SetInfo()
			}
		}
	}
	end {

	}
}
