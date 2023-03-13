# Path to AWS access key
variable "AWS_ACCESS_KEY_PATH" {
    default = "./keys/access_key"
}

# Path to AWS secret key
variable "AWS_SECRET_KEY_PATH" {
    default = "./keys/secret_key"
}

# Path to public key
variable "PUBLIC_KEY_PATH" {
    default = "./keys/terraform_key.pub"
}

# Path to private key
variable "PRIVATE_KEY_PATH" {
    default = "./keys/terraform_key.pem"
}

# IP addresses of the VPC
variable "VPC_CIDR" {
    default = "10.0.0.0/16"
}

# IP addresses of fsociety.local
variable "FSOCIETY_SUBNET_CIDR" {
    default = "10.0.1.0/24"
}

# IP addresses of ecorp.local
variable "ECORP_SUBNET_CIDR" {
    default = "10.0.2.0/24"
}

# IP address of the DC of fsociety.local
variable "FSOCIETY_DC_IP" {
    default = "10.0.1.100"
}

# IP address of the server of fsociety.local
variable "FSOCIETY_SERVER_IP" {
    default = "10.0.1.50"
}

# IP address of the DC of ecorp.local
variable "ECORP_DC_IP" {
    default = "10.0.2.100"
}

# IP address of the server of ecorp.local
variable "ECORP_SERVER_IP" {
    default = "10.0.2.50"
}

# IP address of the attacker
variable "ATTACKER_IP" {
    default = "10.0.1.10"
}

# IP address of public DNS server
variable "PUBLIC_DNS" {
    default = "1.1.1.1"
}

# List of IP addresses allowed to manage instances
variable "MANAGEMENT_IPS" {
    # default = ["1.2.3.4/32"]
    default = ["YOUR_IP_ADDR"]
}

# Name of AWS S3 bucket (must be globally unique!)
variable "S3_BUCKET" {
    # default = "bucket-for-ad-lab"
    default = "YOUR_AWS_S3_BUCKET"
}

# Finds latest 2019 Windows-Server
data "aws_ami" "latest-windows-server" {
    most_recent = true
    owners      = ["amazon"]
    filter {
        name   = "name"
        values = ["Windows_Server-2019-English-Full-Base-*"]
    }
}

# Finds latest Debian
data "aws_ami" "latest-debian" {
    most_recent = true
    owners = ["136693071363"]
    filter {
        name   = "name"
        values = ["debian-10-amd64-*"]
    }
    filter {
        name   = "architecture"
        values = ["x86_64"]
    }
}
