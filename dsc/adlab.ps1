Configuration Lab {
    param
    (
        [Parameter(Mandatory)]
        [pscredential]$safemodeAdministratorCred,
        [Parameter(Mandatory)]
        [pscredential]$domainCred,
        [Parameter(Mandatory)]
        [string]$domainName
    )

    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName NetworkingDsc

    Node "First" {
        
        Computer NewName {
            Name = "First-DC"
        }

        # Install ADDS role
        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        # Optional GUI tools
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

        # Create our AdminUser account 
        User AdminUser {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        # Add our AdminUser to the local Administrators group
        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]AdminUser"
        }

        # Promote our DC
        ADDomain CreateDC {
            DomainName = $domainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\\NTDS'
            LogPath = 'C:\\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }
 
        # Wait for the DC role to come online before we continue provisioning
        WaitForADDomain waitFirstDomain {
            DomainName = $domainName
            DependsOn = "[ADDomain]CreateDC"
        }

        # ??????????
        DnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1', '10.0.1.102'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'regular.user' {
            Ensure     = 'Present'
            UserName   = 'regular.user'
            Password   = (New-Object System.Management.Automation.PSCredential("regular.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'adlab.local'
            Path       = 'CN=Users,DC=adlab,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'roast.user' {
            Ensure     = 'Present'
            UserName   = 'roast.user'
            Password   = (New-Object System.Management.Automation.PSCredential("roast.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'adlab.local'
            Path       = 'CN=Users,DC=adlab,DC=local'
            ServicePrincipalNames = "MSSQL/sql.adlab.local"
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'asrep.user' {
            Ensure     = 'Present'
            UserName   = 'asrep.user'
            Password   = (New-Object System.Management.Automation.PSCredential("asrep.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'adlab.local'
            Path       = 'CN=Users,DC=adlab,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "asrep.user PreAuth Disable" {
            SetScript = {
                Set-ADAccountControl -Identity "asrep.user" -DoesNotRequirePreAuth $true
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "asrep.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]asrep.user"
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
            }
        }

    }

    Node "Second" {

        Computer NewName {
            Name = "Second-DC"
        }

        # Install ADDS role
        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        # Optional GUI tools
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

        # Create our AdminUser account 
        User AdminUser {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        # Add our AdminUser to the local Administrators group
        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]AdminUser"
        }

        # Promote our DC
        ADDomain CreateDC {
            DomainName = $domainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\\NTDS'
            LogPath = 'C:\\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }
 
        # Wait for the DC role to come online before we continue provisioning
        WaitForADDomain waitFirstDomain {
            DomainName = $domainName
            DependsOn = "[ADDomain]CreateDC"
        }

        # ??????????
        DnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1', '10.0.1.101'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'regular.user' {
            Ensure     = 'Present'
            UserName   = 'regular.user'
            Password   = (New-Object System.Management.Automation.PSCredential("regular.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'adlab.local'
            Path       = 'CN=Users,DC=adlab,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'roast.user' {
            Ensure     = 'Present'
            UserName   = 'roast.user'
            Password   = (New-Object System.Management.Automation.PSCredential("roast.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'adlab.local'
            Path       = 'CN=Users,DC=adlab,DC=local'
            ServicePrincipalNames = "MSSQL/sql.adlab.local"
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'asrep.user' {
            Ensure     = 'Present'
            UserName   = 'asrep.user'
            Password   = (New-Object System.Management.Automation.PSCredential("asrep.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'adlab.local'
            Path       = 'CN=Users,DC=adlab,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "asrep.user PreAuth Disable" {
            SetScript = {
                Set-ADAccountControl -Identity "asrep.user" -DoesNotRequirePreAuth $true
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "asrep.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]asrep.user"
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
            }
        }   
    }

    Node "UserServer" {
        
        WaitForAll DC {
            ResourceName      = '[ADUser]asrep'
            NodeName          = 'First-DC'
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
        
        User localuser {
            Ensure = "Present"
            UserName = "local-user"
            Password = $DomainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = "local-user"
            DependsOn = "[User]localuser"
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
            Name = "User-Server"
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }
    }
}

$ConfigData = @{
    AllNodes = @(
        @{
            Nodename                    = "First"
            Role                        = "First DC"
            RetryCount                  = 1
            RetryIntervalSec            = 1
            PsDscAllowPlainTextPassword = $true
        },
        @{
            Nodename                    = "Second"
            Role                        = "Second DC"
            RetryCount                  = 1
            RetryIntervalSec            = 1
            PsDscAllowPlainTextPassword = $true
        },
        @{
            Nodename                    = "UserServer"
            Role                        = "User Server"
            RetryCount                  = 1
            RetryIntervalSec            = 1
            PsDscAllowPlainTextPassword = $true
            PsDscAllowDomainUser        = $true
        }
    )
}

Lab -ConfigurationData $ConfigData `
    -domainName "adlab.local" `
    -domainCred (New-Object System.Management.Automation.PSCredential("admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -safemodeAdministratorCred (New-Object System.Management.Automation.PSCredential("admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))