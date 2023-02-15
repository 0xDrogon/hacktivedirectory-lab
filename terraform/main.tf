provider "aws" {
    region     = "eu-west-1"
    access_key = file(var.AWS_ACCESS_KEY_PATH)
    secret_key = file(var.AWS_SECRET_KEY_PATH)
}

# Our AWS keypair
resource "aws_key_pair" "terraformkey" {
    key_name   = "${terraform.workspace}-terraform-lab"
    public_key = file(var.PUBLIC_KEY_PATH)
}

# Our VPC definition, using a default IP range of 10.0.0.0/16
resource "aws_vpc" "lab-vpc" {
    cidr_block           = var.VPC_CIDR
    enable_dns_support   = true
    enable_dns_hostnames = true
}

# Default route required for the VPC to push traffic via gateway
resource "aws_route" "first-internet-route" {
    route_table_id         = aws_vpc.lab-vpc.main_route_table_id
    destination_cidr_block = "0.0.0.0/0"
    gateway_id             = aws_internet_gateway.lab-vpc-gateway.id
}

# Gateway which allows outbound and inbound internet access to the VPC
resource "aws_internet_gateway" "lab-vpc-gateway" {
    vpc_id = aws_vpc.lab-vpc.id
}

# Create our first subnet (Defaults to 10.0.1.0/24)
resource "aws_subnet" "first-vpc-subnet" {
    vpc_id = aws_vpc.lab-vpc.id
    cidr_block        = var.FSOCIETY_SUBNET_CIDR
    availability_zone = "eu-west-1a"
    tags = {
        Name = "Fsociety Subnet"
    }
}

# Create our second subnet (Defaults to 10.0.2.0/24)
resource "aws_subnet" "second-vpc-subnet" {
    vpc_id = aws_vpc.lab-vpc.id
    cidr_block        = var.ECORP_SUBNET_CIDR
    availability_zone = "eu-west-1a"
    tags = {
        Name = "Ecorp Subnet"
    }
}

# Set DHCP options for delivering things like DNS servers
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

# Add for second ???

# Associate our DHCP configuration with our VPC
resource "aws_vpc_dhcp_options_association" "first-dhcp-assoc" {
    vpc_id          = aws_vpc.lab-vpc.id
    dhcp_options_id = aws_vpc_dhcp_options.first-dhcp.id
}

# Our first domain controller of the "fsociety.local" domain
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
        Name      = "${terraform.workspace}-Fsociety-DC"
    }
    vpc_security_group_ids = [
        aws_security_group.first-sg.id,
    ]
}

# The User server which will be main foothold
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
        Name      = "${terraform.workspace}-Fsociety-Server"
    }
    vpc_security_group_ids = [
        aws_security_group.first-sg.id,
    ]
}

# Our second domain controller of the "ecorp.local" domain
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
        Name      = "${terraform.workspace}-Ecorp-DC"
    }
    vpc_security_group_ids = [
        aws_security_group.second-sg.id,
    ]
}

# The User server which will be main foothold
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
        Name      = "${terraform.workspace}-Ecorp-Server"
    }
    vpc_security_group_ids = [
        aws_security_group.second-sg.id,
    ]
}

# The C2 teamserver
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
        Name      = "${terraform.workspace}-Attacker"
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
    provisioner "remote-exec" {
        inline = [
        "sudo apt update",
        "sudo apt install -y apt-transport-https",
        "sudo apt install -y git",
        "sudo apt install -y python3-pip",
        "sudo apt update",

        # Installs Proxychains
        "sudo apt install -y proxychains4",

        # Installs Nmap
        "sudo apt install -y nmap",

        # Installs Responder
        "git clone https://github.com/lgandx/Responder.git",
        
        # Installs Impacket
        "git clone https://github.com/fortra/impacket.git",
        "cd impacket",
        "sudo python3 -m pip install --upgrade pip",
        "sudo python3 -m pip install .",
        "cd ../"
        ]
    }
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

# Security group for first.local
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

# Security group for second.local
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
    # Allow management from Our IP
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

# Add fsociety.local MOF's to S3
resource "aws_s3_bucket_object" "fsociety-dc-mof" {
    bucket     = var.SSM_S3_BUCKET
    key        = "Lab/FsocietyDC.mof"
    source     = "../dsc/Lab/FsocietyDC.mof"
    etag       = filemd5("../dsc/Lab/FsocietyDC.mof")
}

# Add userserver MOF's to S3
resource "aws_s3_bucket_object" "fsociety-server-mof" {
    bucket     = var.SSM_S3_BUCKET
    key        = "Lab/FsocietyServer.mof"
    source     = "../dsc/Lab/FsocietyServer.mof"
    etag       = filemd5("../dsc/Lab/FsocietyServer.mof")
}

# Add ecorp.local MOF's to S3
resource "aws_s3_bucket_object" "ecorp-dc-mof" {
    bucket     = var.SSM_S3_BUCKET
    key        = "Lab/EcorpDC.mof"
    source     = "../dsc/Lab/EcorpDC.mof"
    etag       = filemd5("../dsc/Lab/EcorpDC.mof")
}

# Add userserver MOF's to S3
resource "aws_s3_bucket_object" "ecorp-server-mof" {
    bucket     = var.SSM_S3_BUCKET
    key        = "Lab/EcorpServer.mof"
    source     = "../dsc/Lab/EcorpServer.mof"
    etag       = filemd5("../dsc/Lab/EcorpServer.mof")
}

# SSM parameters used by DSC
resource "aws_ssm_parameter" "admin-ssm-parameter" {
    name  = "admin"
    type  = "SecureString"
    value = "{\"Username\":\"admin\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "server-user-ssm-parameter" {
    name  = "server-user"
    type  = "SecureString"
    value = "{\"Username\":\"server-user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "workstation-user-ssm-parameter" {
    name  = "workstation-user"
    type  = "SecureString"
    value = "{\"Username\":\"workstation-user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "fsociety-admin-ssm-parameter" {
    name  = "fsociety-admin"
    type  = "SecureString"
    value = "{\"Username\":\"fsociety.local\\\\admin\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "ecorp-admin-ssm-parameter" {
    name  = "ecorp-admin"
    type  = "SecureString"
    value = "{\"Username\":\"ecorp.local\\\\admin\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "mr-robot-ssm-parameter" {
    name  = "mr.robot"
    type  = "SecureString"
    value = "{\"Username\":\"mr.robot\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "dnsadmin-user-ssm-parameter" {
    name  = "dnsadmin.user"
    type  = "SecureString"
    value = "{\"Username\":\"dnsadmin.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "unconstrainer-user-ssm-parameter" {
    name  = "unconstrained.user"
    type  = "SecureString"
    value = "{\"Username\":\"unconstrained.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "constrained-user-ssm-parameter" {
    name  = "constrained.user"
    type  = "SecureString"
    value = "{\"Username\":\"constrained.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "userwrite-user-ssm-parameter" {
    name  = "userwrite.user"
    type  = "SecureString"
    value = "{\"Username\":\"userwrite.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "userall-user-ssm-parameter" {
    name  = "userall.user"
    type  = "SecureString"
    value = "{\"Username\":\"userall.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "compwrite-user-ssm-parameter" {
    name  = "compwrite.user"
    type  = "SecureString"
    value = "{\"Username\":\"compwrite.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "gpowrite-user-ssm-parameter" {
    name  = "gpowrite.user"
    type  = "SecureString"
    value = "{\"Username\":\"gpowrite.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "lapsread-user-ssm-parameter" {
    name  = "lapsread.user"
    type  = "SecureString"
    value = "{\"Username\":\"lapsread.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "groupwrite-user-ssm-parameter" {
    name  = "groupwrite.user"
    type  = "SecureString"
    value = "{\"Username\":\"groupwrite.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "writedacldc-user-ssm-parameter" {
    name  = "writedacldc.user"
    type  = "SecureString"
    value = "{\"Username\":\"writedacldc.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "readgmsa-user-ssm-parameter" {
    name  = "readgmsa.user"
    type  = "SecureString"
    value = "{\"Username\":\"readgmsa.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "clearpass-user-ssm-parameter" {
    name  = "clearpass.user"
    type  = "SecureString"
    value = "{\"Username\":\"clearpass.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "dcsync-user-ssm-parameter" {
    name  = "dcsync.user"
    type  = "SecureString"
    value = "{\"Username\":\"dcsync.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "roast-user-ssm-parameter" {
    name  = "roast.user"
    type  = "SecureString"
    value = "{\"Username\":\"roast.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "asrep-user-ssm-parameter" {
    name  = "asrep.user"
    type  = "SecureString"
    value = "{\"Username\":\"asrep.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "phillip-price-ssm-parameter" {
    name  = "phillip.price"
    type  = "SecureString"
    value = "{\"Username\":\"phillip.price\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "tyrell-wellick-ssm-parameter" {
    name  = "tyrell.wellick"
    type  = "SecureString"
    value = "{\"Username\":\"tyrell.wellick\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "angela-moss-ssm-parameter" {
    name  = "angela.moss"
    type  = "SecureString"
    value = "{\"Username\":\"angela.moss\", \"Password\":\"Password@1\"}"
}

output "fsociety-dc_ip" {
    value       = "${aws_instance.fsociety-dc.public_ip}"
    description = "Public IP of Fsociety-DC"
}

output "fsociety-server_ip" {
    value       = "${aws_instance.fsociety-server.public_ip}"
    description = "Public IP of Fsociety-Server"
}

output "ecorp-dc_ip" {
    value       = "${aws_instance.ecorp-dc.public_ip}"
    description = "Public IP of Ecorp-DC"
}

output "ecorp-server_ip" {
    value       = "${aws_instance.ecorp-server.public_ip}"
    description = "Public IP of Ecorp-Server"
}

output "attacker_ip" {
    value       = "${aws_instance.attacker.public_ip}"
    description = "Public IP of Attacker"
}

output "timestamp" {
    value = formatdate("hh:mm", timestamp())
}

# Apply our DSC via SSM to fsociety.local
resource "aws_ssm_association" "fsociety-dc" {
    name             = "AWS-ApplyDSCMofs"
    association_name = "${terraform.workspace}-Fsociety-DC"
    targets {
        key    = "InstanceIds"
        values = [aws_instance.fsociety-dc.id]
    }
    parameters = {
        MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Lab/FsocietyDC.mof"
        RebootBehavior = "Immediately"
    }
}

# Apply our DSC via SSM to fsociety-server
resource "aws_ssm_association" "fsociety-server" {
    name             = "AWS-ApplyDSCMofs"
    association_name = "${terraform.workspace}-Fsociety-server"
    targets {
        key    = "InstanceIds"
        values = [aws_instance.fsociety-server.id]
    }
    parameters = {
        MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Lab/FsocietyServer.mof"
        RebootBehavior = "Immediately"
    }
}

# Apply our DSC via SSM to ecorp.local
resource "aws_ssm_association" "ecorp-dc" {
    name             = "AWS-ApplyDSCMofs"
    association_name = "${terraform.workspace}-Ecorp-DC"
    targets {
        key    = "InstanceIds"
        values = [aws_instance.ecorp-dc.id]
    }
    parameters = {
        MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Lab/EcorpDC.mof"
        RebootBehavior = "Immediately"
    }
}

# Apply our DSC via SSM to ecorp-server
resource "aws_ssm_association" "ecorp-server" {
    name             = "AWS-ApplyDSCMofs"
    association_name = "${terraform.workspace}-Ecorp-server"
    targets {
        key    = "InstanceIds"
        values = [aws_instance.ecorp-server.id]
    }
    parameters = {
        MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Lab/EcorpServer.mof"
        RebootBehavior = "Immediately"
    }
}