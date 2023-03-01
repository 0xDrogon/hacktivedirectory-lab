configuration Lab {

    param
    (
        [Parameter(Mandatory)]
        [pscredential]$safemodeAdministratorCred,
        [Parameter(Mandatory)]
        [pscredential]$domainCred,
        [Parameter(Mandatory)]
        [string]$firstDomainName,
        [Parameter(Mandatory)]
        [string]$secondDomainName,
        [Parameter(Mandatory)]
        [pscredential]$firstDomainCred,
        [Parameter(Mandatory)]
        [pscredential]$secondDomainCred
    )

    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName SqlServerDsc

    Node "DC01" {

        Computer NewName {
            Name = "DC01"
        }
        
        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        WindowsFeature ADDSTools {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }

        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }

        User AdminUser {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]AdminUser"
        }

        ADDomain CreateDC {
            DomainName = $firstDomainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\NTDS'
            LogPath = 'C:\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            DependsOn = "[ADDomain]CreateDC"
        }

        DnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1', '10.0.2.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script SetConditionalForwardedZone {
            GetScript = { return @{ } }
            TestScript = {
                $zone = Get-DnsServerZone -Name $using:secondDomainName -ErrorAction SilentlyContinue
                if ($zone -ne $null -and $zone.ZoneType -eq 'Forwarder') {
                    return $true
                }

                return $false
            }
            SetScript = {
                $ForwardDomainName = $using:secondDomainName
                $IpAddresses = @("10.0.2.100")
                Add-DnsServerConditionalForwarderZone -Name "$ForwardDomainName" -ReplicationScope "Domain" -MasterServers $IpAddresses
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADGroup DomainAdmin {
            Ensure = "Present"
            GroupName = "Domain Admins"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'mr.robot' {
            Ensure     = 'Present'
            UserName   = 'mr.robot'
            Password   = (New-Object System.Management.Automation.PSCredential("mr.robot", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'dnsadmin.user' {
            Ensure     = 'Present'
            UserName   = 'dnsadmin.user'
            Password   = (New-Object System.Management.Automation.PSCredential("dnsadmin.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADGroup DnsAdmin {
            Ensure = "Present"
            GroupName = "DnsAdmins"
            MembersToInclude = "dnsadmin.user"
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]dnsadmin.user"
        }

        ADUser 'unconstrained.user' {
            Ensure     = 'Present'
            UserName   = 'unconstrained.user'
            Password   = (New-Object System.Management.Automation.PSCredential("unconstrained.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "unconstrained.user Unconstrained Delegation Set" {
            SetScript = {
                Set-ADAccountControl -Identity "unconstrained.user" -TrustedForDelegation $True
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "unconstrained.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]unconstrained.user"
        }

        ADUser 'constrained.user' {
            Ensure     = 'Present'
            UserName   = 'constrained.user'
            Password   = (New-Object System.Management.Automation.PSCredential("constrained.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "constrained.user constrained Delegation Set" {
            SetScript = {
                $user = (Get-ADUser -Identity "constrained.user").DistinguishedName
                Set-ADObject -Identity $user -Add @{"msDS-AllowedToDelegateTo" = @("CIFS/DC01","CIFS/DC01.fsociety.local","CIFS/DC01.fsociety.local/fsociety.local")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "constrained.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]constrained.user"
        }

        ADUser 'userwrite.user' {
            Ensure     = 'Present'
            UserName   = 'userwrite.user'
            Password   = (New-Object System.Management.Automation.PSCredential("userwrite.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "userwrite.user Write Permissions on User Node" {
            SetScript = {
                $Destination = (Get-ADUser -Identity "constrained.user").DistinguishedName
                $Source = (Get-ADUser -Identity "userwrite.user").sid
                $Rights = "GenericWrite"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "userwrite.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]userwrite.user"
        }

        ADUser 'userall.user' {
            Ensure     = 'Present'
            UserName   = 'userall.user'
            Password   = (New-Object System.Management.Automation.PSCredential("userall.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "userall.user GenericAll Permissions on User Node" {
            SetScript = {
                $Destination = (Get-ADUser -Identity "userwrite.user").DistinguishedName
                $Source = (Get-ADUser -Identity "userall.user").sid
                $Rights = "GenericAll"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "userall.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]userall.user"
        }

        ADUser 'leslie.romero' {
            Ensure     = 'Present'
            UserName   = 'leslie.romero'
            Password   = (New-Object System.Management.Automation.PSCredential("leslie.romero", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "leslie.romero Password in AD" {
            SetScript = {
                Set-ADUser -Identity "leslie.romero" -Description "DELETE THIS LATER! Password: RGFyayBBcm15"
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "leslie.romero" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]leslie.romero"
        }

        ADUser 'darlene.alderson' {
            Ensure     = 'Present'
            UserName   = 'darlene.alderson'
            Password   = (New-Object System.Management.Automation.PSCredential("darlene.alderson", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            ServicePrincipalNames = "MSSQL/sql.fsociety.local"
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'angela.moss' {
            Ensure     = 'Present'
            UserName   = 'angela.moss'
            Password   = (New-Object System.Management.Automation.PSCredential("angela.moss", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "angela.moss PreAuth Disable" {
            SetScript = {
                Set-ADAccountControl -Identity "angela.moss" -DoesNotRequirePreAuth $true
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "angela.moss" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]angela.moss"
        }

        ADUser leon {
            Ensure     = 'Present'
            UserName   = 'leon'
            Password   = (New-Object System.Management.Automation.PSCredential("leon", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'fsociety.local'
            Path       = 'CN=Users,DC=fsociety,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Fsociety-Server-RDP" {
            SetScript = {
                Start-Sleep -Seconds 300
                Invoke-Command -ComputerName "SRV01" -Scriptblock {net localgroup "Remote Desktop Users" "fsociety\domain users" /add}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "SRV01" ) } 
            }
            PsDscRunAsCredential = $firstDomainCred
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Fsociety-Server constrained Delegation Set" {
            SetScript = {
                $comp = (Get-ADComputer -Identity "SRV01").DistinguishedName
                Set-ADObject -Identity $comp -Add @{"msDS-AllowedToDelegateTo" = @("HOST/DC01","HOST/DC01.fsociety.local","HOST/DC01.fsociety.local/fsociety.local")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "SRV01" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script DisableSMBSign {
            GetScript = { 
                return @{ } 
            }
            TestScript = {
                $false
            }
            SetScript = {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" RequireSecuritySignature 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" RequireSecuritySignature 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" EnableSecuritySignature 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" EnableSecuritySignature 0
            }
        }

        Script DisableDefender {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }
            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }
            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
                $global:DSCMachineStatus = 1
            }
        }
    }

    Node "SRV01" {
        
        WaitForAll DC {
            ResourceName      = '[ADUser]leon'
            NodeName          = 'DC01'
            RetryIntervalSec  = 60
            RetryCount        = 15
        }
        
        FirewallProfile DisablePublic {
            Enabled = "False"
            Name    = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name    = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name    = "Domain"
        }

        WindowsFeature WebServer {
            Ensure = "Present"
            Name   = "Web-Server"
        }

        WindowsFeature NetFramework45 {
            Name   = 'NET-Framework-45-Core'
            Ensure = 'Present'
        }

        SqlSetup InstallSQL {
            InstanceName        = 'MSSQLSERVER'
            Features            = 'SQLENGINE'
            SourcePath          = 'C:\SQL2022'
            SQLSysAdminAccounts = @('Administrators')
            TcpEnabled          = $true
            DependsOn           = '[WindowsFeature]NetFramework45'
        }
        
        User ServerUser {
            Ensure   = "Present"
            UserName = "server-user"
            Password = $DomainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = "server-user"
            DependsOn = "[User]ServerUser"
        }

        DnsServerAddress DnsServerAddress {
            Address        = '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn      = "[Group]Administrators"
        }

        Script DisableDefender {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }
            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }
            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
            }
        }

        Script DisableSMBSign {
            GetScript = { 
                return @{ } 
            }
            TestScript = {
                $false
            }
            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
                Set-SmbServerConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            WaitForValidCredentials = $true
            WaitTimeout = 300
            DependsOn = "[DnsServerAddress]DnsServerAddress"
        }

        Computer JoinDomain {
            Name = "SRV01"
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }
    }

    Node "DC02" {

        Computer NewName {
            Name = "DC02"
        }
        
        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        WindowsFeature ADDSTools {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }

        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }

        User AdminUser {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]AdminUser"
        }
        
        ADDomain CreateDC {
            DomainName = $secondDomainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\NTDS'
            LogPath = 'C:\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WaitForADDomain waitSecondDomain {
            DomainName = $secondDomainName
            DependsOn = "[ADDomain]CreateDC"
        }

        DnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1', '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        Script SetConditionalForwardedZone {
            GetScript = { return @{ } }
            TestScript = {
                $zone = Get-DnsServerZone -Name $using:firstDomainName -ErrorAction SilentlyContinue
                if ($zone -ne $null -and $zone.ZoneType -eq 'Forwarder') {
                    return $true
                }

                return $false
            }
            SetScript = {
                $ForwardDomainName = $using:firstDomainName
                $IpAddresses = @("10.0.1.100")
                Add-DnsServerConditionalForwarderZone -Name "$ForwardDomainName" -ReplicationScope "Domain" -MasterServers $IpAddresses
            }
        }

        ADGroup DomainAdmin {
            Ensure = "Present"
            GroupName = "Domain Admins"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        ADUser 'phillip.price' {
            Ensure     = 'Present'
            UserName   = 'phillip.price'
            Password   = (New-Object System.Management.Automation.PSCredential("phillip.price", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'ecorp.local'
            Path       = 'CN=Users,DC=ecorp,DC=local'
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        ADUser 'tyrell.wellick' {
            Ensure     = 'Present'
            UserName   = 'tyrell.wellick'
            Password   = (New-Object System.Management.Automation.PSCredential("tyrell.wellick", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'ecorp.local'
            Path       = 'CN=Users,DC=ecorp,DC=local'
            ServicePrincipalNames = "MSSQL/sql.ecorp.local"
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        ADUser 'terry.colby' {
            Ensure     = 'Present'
            UserName   = 'terry.colby'
            Password   = (New-Object System.Management.Automation.PSCredential("terry.colby", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'ecorp.local'
            Path       = 'CN=Users,DC=ecorp,DC=local'
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            WaitTimeout = 600
            RestartCount = 2
            DependsOn = "[Script]SetConditionalForwardedZone"
        }

        ADDomainTrust DomainTrust {
            TargetDomainName = $firstDomainName
            TargetCredential = $firstDomainCred
            TrustType = "External"
            TrustDirection = "Bidirectional"
            SourceDomainName = $secondDomainName
            DependsOn = "[WaitForADDomain]waitFirstDomain"
            Ensure = "Present"
        }

        Script "Ecorp-Server-RDP" {
            SetScript = {
                Start-Sleep -Seconds 300
                Invoke-Command -ComputerName "SRV02" -Scriptblock {net localgroup "Remote Desktop Users" "ecorp\domain users" /add}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "SRV02" ) } 
            }
            PsDscRunAsCredential = $secondDomainCred
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Ecorp-Server constrained Delegation Set" {
            SetScript = {
                $comp = (Get-ADComputer -Identity "SRV02").DistinguishedName
                Set-ADObject -Identity $comp -Add @{"msDS-AllowedToDelegateTo" = @("HOST/DC02","HOST/DC02.ecorp.local","HOST/DC02.ecorp.local/ecorp.local")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "SRV02" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script DisableSMBSign {
            GetScript = { 
                return @{ } 
            }
            TestScript = {
                $false
            }
            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
                Set-SmbServerConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }

        Script DisableDefender {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }
            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }
            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
                $global:DSCMachineStatus = 1
            }
        }
    }

    Node "SRV02" {
        
        WaitForAll DC {
            ResourceName      = '[ADUser]terry.colby'
            NodeName          = 'DC02'
            RetryIntervalSec  = 60
            RetryCount        = 15
        }
        
        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }

        WindowsFeature FTPServer {
            Ensure = "Present"
            Name   = "Web-FTP-Server"
        }

        WindowsFeature FTPService {
            Ensure = "Present"
            Name   = "Web-FTP-Service"
        }

        WindowsFeature FTPExtensibility {
            Ensure = "Present"
            Name   = "Web-FTP-Ext"
        }
        
        User ServerUser {
            Ensure = "Present"
            UserName = "server-user"
            Password = $DomainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = "server-user"
            DependsOn = "[User]ServerUser"
        }

        DnsServerAddress DnsServerAddress {
            Address        = '10.0.2.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn      = "[Group]Administrators"
        }

        Script DisableDefender {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }
            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }
            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
            }
        }

        Script DisableSMBSign {
            GetScript = { 
                return @{ } 
            }
            TestScript = {
                $false
            }
            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
                Set-SmbServerConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }

        WaitForADDomain waitSecondDomain {
            DomainName = $secondDomainName
            Credential = $secondDomainCred
            WaitForValidCredentials = $true
            WaitTimeout = 300
            DependsOn = "[DnsServerAddress]DnsServerAddress"
        }

        Computer JoinDomain {
            Name = "SRV02"
            DomainName = $secondDomainName
            Credential = $secondDomainCred
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }
    }
}

$ConfigData = @{
    AllNodes = @(
        @{
            Nodename                    = "DC01"
            Role                        = "DC01"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
        },
        @{
            Nodename                    = "SRV01"
            Role                        = "SRV01"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
            PsDscAllowDomainUser        = $true
        },
        @{
            Nodename                    = "DC02"
            Role                        = "DC02"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
        },
        @{
            Nodename                    = "SRV02"
            Role                        = "SRV02"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
            PsDscAllowDomainUser        = $true
        }
    )
}

Lab -ConfigurationData $ConfigData `
    -firstDomainName "fsociety.local" `
    -secondDomainName "ecorp.local" `
    -domainCred (New-Object System.Management.Automation.PSCredential("admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -safemodeAdministratorCred (New-Object System.Management.Automation.PSCredential("admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -firstDomainCred (New-Object System.Management.Automation.PSCredential("fsociety-admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -secondDomainCred (New-Object System.Management.Automation.PSCredential("ecorp-admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) 
