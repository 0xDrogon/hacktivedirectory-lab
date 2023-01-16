provider "aws" {
    region     = "eu-west-1"
    access_key = file(var.AWS_ACCESS_KEY_PATH)
    secret_key = file(var.AWS_SECRET_KEY_PATH)
}

# Our AWS keypair
resource "aws_key_pair" "terraformkey" {
    key_name   = "${terraform.workspace}-terraform-lab"
    public_key = file(var.TERRAFORM_PUBLIC_KEY_PATH)
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

    cidr_block        = var.FIRST_SUBNET_CIDR
    availability_zone = "eu-west-1"

    tags = {
        Name = "First Subnet"
    }
}

# Set DHCP options for delivering things like DNS servers
resource "aws_vpc_dhcp_options" "first-dhcp" {
    domain_name          = "ad-lab.local"
    domain_name_servers  = [var.FIRST_DC_IP, var.PUBLIC_DNS]
    ntp_servers          = [var.FIRST_DC_IP]
    netbios_name_servers = [var.FIRST_DC_IP]
    netbios_node_type    = 2

    tags = {
        Name = "First DHCP"
    }
}

# Associate our DHCP configuration with our VPC
resource "aws_vpc_dhcp_options_association" "first-dhcp-assoc" {
    vpc_id          = aws_vpc.lab-vpc.id
    dhcp_options_id = aws_vpc_dhcp_options.first-dhcp.id
}

# First domain controller of the "ad-lab.local" domain
resource "aws_instance" "first-dc" {
    ami                         = var.WINDOWS_SERVER_AMI
    instance_type               = "t2.small"
    key_name                    = aws_key_pair.terraformkey.key_name
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.first-vpc-subnet.id
    private_ip                  = var.FIRST_DC_IP
    iam_instance_profile        = var.ENVIRONMENT == "deploy" ? null : aws_iam_instance_profile.ssm_instance_profile.0.name

    tags = {
        Workspace = "${terraform.workspace}"
        Name = "${terraform.workspace}-First-DC"
    }

    vpc_security_group_ids = [
        aws_security_group.first-sg.id,
    ]
}

# Second domain controller of the "ad-lab.local" domain
resource "aws_instance" "second-dc" {
    ami                         = var.WINDOWS_SERVER_AMI
    instance_type               = "t2.small"
    key_name                    = aws_key_pair.terraformkey.key_name
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.first-vpc-subnet.id
    private_ip                  = var.SECOND_DC_IP
    iam_instance_profile        = var.ENVIRONMENT == "deploy" ? null : aws_iam_instance_profile.ssm_instance_profile.0.name

    tags = {
        Workspace = "${terraform.workspace}"
        Name      = "${terraform.workspace}-Second-DC"
    }

    vpc_security_group_ids = [
        aws_security_group.second-sg.id,
    ]
}

# The User server which will be main foothold
resource "aws_instance" "user-server" {
    ami                         = var.WINDOWS_SERVER_AMI
    instance_type               = "t2.small"
    key_name                    = aws_key_pair.terraformkey.key_name
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.first-vpc-subnet.id
    private_ip                  = var.USER_SERVER_IP
    iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

    tags = {
        Workspace = "${terraform.workspace}"
        Name      = "${terraform.workspace}-User-Server"
    }

    vpc_security_group_ids = [
        aws_security_group.first-sg.id,
    ]
}

# The C2 teamserver
resource "aws_instance" "attack-server" {
    ami                         = var.DEBIAN_AMI
    instance_type               = "t2.small"
    key_name                    = aws_key_pair.terraformkey.key_name
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.first-vpc-subnet.id
    private_ip                  = var.ATTACK_SERVER_IP
    iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

    tags = {
        Workspace = "${terraform.workspace}"
        Name      = "${terraform.workspace}-Attack-Server"
    }

    vpc_security_group_ids = [
        aws_security_group.first-sg.id,
    ]
}