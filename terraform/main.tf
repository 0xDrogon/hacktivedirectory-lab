provider "aws" {
    region     = "eu-west-1"
    access_key = file(var.AWS_ACCESS_KEY_PATH)
    secret_key = file(var.AWS_SECRET_KEY_PATH)
}

# AWS keypair
resource "aws_key_pair" "terraformkey" {
    key_name   = "${terraform.workspace}-terraform-lab"
    public_key = file(var.PUBLIC_KEY_PATH)
}

# Creates VPC
resource "aws_vpc" "lab-vpc" {
    cidr_block           = var.VPC_CIDR
    enable_dns_support   = true
    enable_dns_hostnames = true
}

# Adds default route to push traffic via gateway
resource "aws_route" "first-internet-route" {
    route_table_id         = aws_vpc.lab-vpc.main_route_table_id
    destination_cidr_block = "0.0.0.0/0"
    gateway_id             = aws_internet_gateway.lab-vpc-gateway.id
}

# Gateway which allows outbound and inbound internet access to the VPC
resource "aws_internet_gateway" "lab-vpc-gateway" {
    vpc_id = aws_vpc.lab-vpc.id
}

# Creates first subnet
resource "aws_subnet" "first-vpc-subnet" {
    vpc_id = aws_vpc.lab-vpc.id
    cidr_block        = var.FSOCIETY_SUBNET_CIDR
    availability_zone = "eu-west-1a"
    tags = {
        Name = "Fsociety Subnet"
    }
}

# Creates second subnet
resource "aws_subnet" "second-vpc-subnet" {
    vpc_id = aws_vpc.lab-vpc.id
    cidr_block        = var.ECORP_SUBNET_CIDR
    availability_zone = "eu-west-1a"
    tags = {
        Name = "Ecorp Subnet"
    }
}

# Sets DHCP options (delivers DNS servers)
resource "aws_vpc_dhcp_options" "first-dhcp" {
    domain_name          = "fsociety.local"
    domain_name_servers  = [var.FSOCIETY_DC_IP, var.PUBLIC_DNS]
    ntp_servers          = [var.FSOCIETY_DC_IP]
    netbios_name_servers = [var.FSOCIETY_DC_IP]
    netbios_node_type    = 2
    tags = {
        Name = "Fsociety DHCP"
    }
}

# Associates DHCP configuration with the VPC
resource "aws_vpc_dhcp_options_association" "first-dhcp-assoc" {
    vpc_id          = aws_vpc.lab-vpc.id
    dhcp_options_id = aws_vpc_dhcp_options.first-dhcp.id
}

# DC of the fsociety.local domain
resource "aws_instance" "fsociety-dc" {
    ami                         = data.aws_ami.latest-windows-server.image_id
    instance_type               = "t2.small"
    key_name                    = aws_key_pair.terraformkey.key_name
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.first-vpc-subnet.id
    private_ip                  = var.FSOCIETY_DC_IP
    iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name
    tags = {
        Workspace = "${terraform.workspace}"
        Name      = "DC01"
    }
    vpc_security_group_ids = [
        aws_security_group.first-sg.id,
    ]
}

# Server of the fsociety.local domain
resource "aws_instance" "fsociety-server" {
    ami                         = data.aws_ami.latest-windows-server.image_id
    instance_type               = "t2.small"
    key_name                    = aws_key_pair.terraformkey.key_name
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.first-vpc-subnet.id
    private_ip                  = var.FSOCIETY_SERVER_IP
    iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name
    tags = {
        Workspace = "${terraform.workspace}"
        Name      = "SRV01"
    }
    vpc_security_group_ids = [
        aws_security_group.first-sg.id,
    ]
    user_data = <<EOF
    <powershell>
        Invoke-WebRequest https://drive.tecnico.ulisboa.pt/download/1132973718312167 -OutFile C:\sql_server_2022_dev_x64.iso
        New-Item -Path C:\SQL2022 -ItemType Directory
        $mountResult = Mount-DiskImage -ImagePath 'C:\sql_server_2022_dev_x64.iso' -PassThru
        $volumeInfo = $mountResult | Get-Volume
        $driveInfo = Get-PSDrive -Name $volumeInfo.DriveLetter
        Copy-Item -Path ( Join-Path -Path $driveInfo.Root -ChildPath '*' ) -Destination C:\SQL2022\ -Recurse
        Dismount-DiskImage -ImagePath 'C:\sql_server_2022_dev_x64.iso'
    </powershell>
    EOF
}

# DC of the ecorp.local domain
resource "aws_instance" "ecorp-dc" {
    ami                         = data.aws_ami.latest-windows-server.image_id
    instance_type               = "t2.small"
    key_name                    = aws_key_pair.terraformkey.key_name
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.second-vpc-subnet.id
    private_ip                  = var.ECORP_DC_IP
    iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name
    tags = {
        Workspace = "${terraform.workspace}"
        Name      = "DC02"
    }
    vpc_security_group_ids = [
        aws_security_group.second-sg.id,
    ]
}

# Server of the ecorp.local domain
resource "aws_instance" "ecorp-server" {
    ami                         = data.aws_ami.latest-windows-server.image_id
    instance_type               = "t2.small"
    key_name                    = aws_key_pair.terraformkey.key_name
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.second-vpc-subnet.id
    private_ip                  = var.ECORP_SERVER_IP
    iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name
    tags = {
        Workspace = "${terraform.workspace}"
        Name      = "SRV02"
    }
    vpc_security_group_ids = [
        aws_security_group.second-sg.id,
    ]
    user_data = <<EOF
    <powershell>
        Install-WindowsFeature Web-FTP-Server -IncludeAllSubFeature
        Import-Module WebAdministration
        $FTPSiteName = 'Default FTP Site'
        $FTPRootDir = 'C:\inetpub\ftproot'
        $FTPPort = 21
        New-WebFtpSite -Name $FTPSiteName -Port $FTPPort -PhysicalPath $FTPRootDir
        Restart-WebItem "IIS:\Sites\$FTPSiteName"
    </powershell>
    EOF
}

# Attacker
resource "aws_instance" "attacker" {
    ami                         = data.aws_ami.latest-debian.image_id
    instance_type               = "t2.small"
    key_name                    = aws_key_pair.terraformkey.key_name
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.first-vpc-subnet.id
    private_ip                  = var.ATTACKER_IP
    iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name
    tags = {
        Workspace = "${terraform.workspace}"
        Name      = "Attacker"
    }
    vpc_security_group_ids = [
        aws_security_group.first-sg.id,
    ]
}
resource "null_resource" "attacker-setup" {
    connection {
        type        = "ssh"
        host        = aws_instance.attacker.public_ip
        user        = "admin"
        port        = "22"
        private_key = file(var.PRIVATE_KEY_PATH)
        agent       = false
    }
    provisioner "file" {
        source      = "../utils/wordlists"
        destination = "wordlists"
    }
    provisioner "remote-exec" {
        inline = [
        # Initial setup
        "sudo hostnamectl set-hostname attacker",
        "sudo apt update",
        "sudo apt install -y apt-transport-https",
        "sudo apt install -y git",
        "sudo apt install -y python3-pip",
        "sudo apt update",
        # Installs dig & nslookup
        "sudo apt install -y dnsutils",
        # Installs Proxychains
        "sudo apt install -y proxychains4",
        "sudo sed -i 's/9050/1080/g' /etc/proxychains4.conf",
        # Installs Nmap
        "sudo apt install -y nmap",
        # Installs HashCat
        "sudo apt install -y hashcat",
        # Installs Kerbrute
        "wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute",
        "chmod +x kerbrute",
        # Installs Responder
        "git clone https://github.com/lgandx/Responder.git",
        "cd Responder",
        "sudo pip install netifaces",
        "cd ..",
        # Installs Impacket
        "git clone https://github.com/fortra/impacket.git",
        "cd impacket",
        "sudo python3 -m pip install --upgrade pip",
        "sudo python3 -m pip install .",
        "cd .."
        ]
    }
}

# Creates S3 bucket to store MOF files
resource "aws_s3_bucket" "ad-lab-bucket" {
    bucket = var.S3_BUCKET
}
resource "aws_s3_bucket_lifecycle_configuration" "ad-lab-bucket-lifecycle" {
    bucket = aws_s3_bucket.ad-lab-bucket.id
    rule {
        status = "Enabled"
        id     = "expire_all_files"
        expiration {
            days = 1
        }
    }
}

# Adds MOF files to the bucket
resource "aws_s3_object" "fsociety-dc-mof" {
    bucket     = aws_s3_bucket.ad-lab-bucket.id
    key        = "Lab/DC01.mof"
    source     = "../dsc/Lab/DC01.mof"
    etag       = filemd5("../dsc/Lab/DC01.mof")
}
resource "aws_s3_object" "fsociety-server-mof" {
    bucket     = aws_s3_bucket.ad-lab-bucket.id
    key        = "Lab/SRV01.mof"
    source     = "../dsc/Lab/SRV01.mof"
    etag       = filemd5("../dsc/Lab/SRV01.mof")
}
resource "aws_s3_object" "ecorp-dc-mof" {
    bucket     = aws_s3_bucket.ad-lab-bucket.id
    key        = "Lab/DC02.mof"
    source     = "../dsc/Lab/DC02.mof"
    etag       = filemd5("../dsc/Lab/DC02.mof")
}
resource "aws_s3_object" "ecorp-server-mof" {
    bucket     = aws_s3_bucket.ad-lab-bucket.id
    key        = "Lab/SRV02.mof"
    source     = "../dsc/Lab/SRV02.mof"
    etag       = filemd5("../dsc/Lab/SRV02.mof")
}

# IAM Role required to access SSM from EC2
resource "aws_iam_role" "ssm_role" {
    name               = "${terraform.workspace}_ssm_role_default"
    count              = 1
    assume_role_policy = <<EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
        "Action": "sts:AssumeRole",
        "Principal": {
            "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
        }
    ]
    }
    EOF
}
resource "aws_iam_role_policy_attachment" "ssm_role_policy" {
    role       = aws_iam_role.ssm_role.0.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}
resource "aws_iam_instance_profile" "ssm_instance_profile" {
    name  = "${terraform.workspace}_ssm_instance_profile"
    role  = aws_iam_role.ssm_role.0.name
}

# Security group for fsociety.local
resource "aws_security_group" "first-sg" {
    vpc_id = aws_vpc.lab-vpc.id
    # Allow second zone to first
    ingress {
        protocol    = "-1"
        cidr_blocks = [var.ECORP_SUBNET_CIDR]
        from_port   = 0
        to_port     = 0
    }
    ingress {
        protocol    = "-1"
        cidr_blocks = [var.FSOCIETY_SUBNET_CIDR]
        from_port   = 0
        to_port     = 0
    }
    # Allow management from our IP
    ingress {
        protocol    = "-1"
        cidr_blocks = var.MANAGEMENT_IPS
        from_port   = 0
        to_port     = 0
    }
    # Allow global outbound
    egress {
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        from_port   = 0
        to_port     = 0
    }
}

# Security group for ecorp.local
resource "aws_security_group" "second-sg" {
    vpc_id = aws_vpc.lab-vpc.id
    # Allow secure zone to first
    ingress {
        protocol    = "-1"
        cidr_blocks = [var.FSOCIETY_SUBNET_CIDR]
        from_port   = 0
        to_port     = 0
    }
    ingress {
        protocol    = "-1"
        cidr_blocks = [var.ECORP_SUBNET_CIDR]
        from_port   = 0
        to_port     = 0
    }
    # Allow management from our IP
    ingress {
        protocol    = "-1"
        cidr_blocks = var.MANAGEMENT_IPS
        from_port   = 0
        to_port     = 0
    }
    # Allow global outbound
    egress {
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        from_port   = 0
        to_port     = 0
    }
}

# SSM parameters used by DSC (users and passwords)
resource "aws_ssm_parameter" "admin-ssm-parameter" {
    name  = "admin"
    type  = "SecureString"
    value = "{\"Username\":\"admin\", \"Password\":\"I_4m_D0m41n_Adm1n15tr4t0r\"}"
}
resource "aws_ssm_parameter" "fsociety-admin-ssm-parameter" {
    name  = "fsociety-admin"
    type  = "SecureString"
    value = "{\"Username\":\"fsociety.local\\\\admin\", \"Password\":\"I_4m_D0m41n_Adm1n15tr4t0r\"}"
}
resource "aws_ssm_parameter" "ecorp-admin-ssm-parameter" {
    name  = "ecorp-admin"
    type  = "SecureString"
    value = "{\"Username\":\"ecorp.local\\\\admin\", \"Password\":\"I_4m_D0m41n_Adm1n15tr4t0r\"}"
}
resource "aws_ssm_parameter" "server-user-ssm-parameter" {
    name  = "server-user"
    type  = "SecureString"
    value = "{\"Username\":\"server-user\", \"Password\":\"I_4m_S3rv3r_U53r\"}"
}
resource "aws_ssm_parameter" "mr-robot-ssm-parameter" {
    # DNS admin
    name  = "mr.robot"
    type  = "SecureString"
    value = "{\"Username\":\"mr.robot\", \"Password\":\"!LeAvE_mE_hErE!\"}"
}
resource "aws_ssm_parameter" "elliot-alderson-ssm-parameter" {
    # User with Constrained Delegation
    name  = "elliot.alderson"
    type  = "SecureString"
    value = "{\"Username\":\"elliot.alderson\", \"Password\":\"ShAyLa_QwErTy_KrIsTa\"}"
}
resource "aws_ssm_parameter" "darlene-alderson-ssm-parameter" {
    # User with Unconstrained Delegation
    name  = "darlene.alderson"
    type  = "SecureString"
    value = "{\"Username\":\"darlene.alderson\", \"Password\":\"M00np1&\"}"
}
resource "aws_ssm_parameter" "leslie-romero-ssm-parameter" {
    # User with cleartext password in the description
    name  = "leslie.romero"
    type  = "SecureString"
    value = "{\"Username\":\"leslie.romero\", \"Password\":\"RGFyayBBcm15\"}"
}
resource "aws_ssm_parameter" "angela-moss-ssm-parameter" {
    # User with Kerberos preauthentication disabled
    name  = "angela.moss"
    type  = "SecureString"
    value = "{\"Username\":\"angela.moss\", \"Password\":\"Jogging1988\"}"
}
resource "aws_ssm_parameter" "leon-ssm-parameter" {
    # User with weak password
    name  = "leon"
    type  = "SecureString"
    value = "{\"Username\":\"leon\", \"Password\":\"Password123\"}"
}
resource "aws_ssm_parameter" "phillip-price-ssm-parameter" {
    name  = "phillip.price"
    type  = "SecureString"
    value = "{\"Username\":\"phillip.price\", \"Password\":\"Ecorp0704\"}"
}
resource "aws_ssm_parameter" "terry-colby-ssm-parameter" {
    name  = "terry.colby"
    type  = "SecureString"
    value = "{\"Username\":\"terry.colby\", \"Password\":\"Ecorp0508\"}"
}
resource "aws_ssm_parameter" "tyrell-wellick-ssm-parameter" {
    name  = "tyrell.wellick"
    type  = "SecureString"
    value = "{\"Username\":\"tyrell.wellick\", \"Password\":\"VastraGotalandsIan1982\"}"
}

# Outputs
output "dc01_ip" {
    value       = "${aws_instance.fsociety-dc.public_ip}"
    description = "Public IP of DC01"
}
output "srv01_ip" {
    value       = "${aws_instance.fsociety-server.public_ip}"
    description = "Public IP of SRV01"
}
output "dc02_ip" {
    value       = "${aws_instance.ecorp-dc.public_ip}"
    description = "Public IP of DC02"
}
output "srv02_ip" {
    value       = "${aws_instance.ecorp-server.public_ip}"
    description = "Public IP of SRV02"
}
output "attacker_ip" {
    value       = "${aws_instance.attacker.public_ip}"
    description = "Public IP of Attacker"
}
output "timestamp" {
    value = formatdate("hh:mm", timestamp())
}

# Applying the DSC to the windows machines
resource "aws_ssm_association" "fsociety-dc" {
    name             = "AWS-ApplyDSCMofs"
    association_name = "DC01"
    targets {
        key    = "InstanceIds"
        values = [aws_instance.fsociety-dc.id]
    }
    parameters = {
        MofsToApply    = "s3:${var.S3_BUCKET}:Lab/DC01.mof"
        RebootBehavior = "Immediately"
    }
}
resource "aws_ssm_association" "fsociety-server" {
    name             = "AWS-ApplyDSCMofs"
    association_name = "SRV01"
    targets {
        key    = "InstanceIds"
        values = [aws_instance.fsociety-server.id]
    }
    parameters = {
        MofsToApply    = "s3:${var.S3_BUCKET}:Lab/SRV01.mof"
        RebootBehavior = "Immediately"
    }
}
resource "aws_ssm_association" "ecorp-dc" {
    name             = "AWS-ApplyDSCMofs"
    association_name = "DC02"
    targets {
        key    = "InstanceIds"
        values = [aws_instance.ecorp-dc.id]
    }
    parameters = {
        MofsToApply    = "s3:${var.S3_BUCKET}:Lab/DC02.mof"
        RebootBehavior = "Immediately"
    }
}
resource "aws_ssm_association" "ecorp-server" {
    name             = "AWS-ApplyDSCMofs"
    association_name = "SRV02"
    targets {
        key    = "InstanceIds"
        values = [aws_instance.ecorp-server.id]
    }
    parameters = {
        MofsToApply    = "s3:${var.S3_BUCKET}:Lab/SRV02.mof"
        RebootBehavior = "Immediately"
    }
}