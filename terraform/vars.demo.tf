# This a demo vars.tf
# This file is not completed as there is sensitive information that should not be pushed to git (MANAGEMENT_IPS and SSM_S3_BUCKET)

variable "AWS_ACCESS_KEY_PATH" {
    default = "./keys/access_key"
}

variable "AWS_SECRET_KEY_PATH" {
    default = "./keys/secret_key"
}

variable "TERRAFORM_PUBLIC_KEY_PATH" {
    default = "./keys/terraform_key.pub"
}

variable "TERRAFORM_PRIVATE_KEY_PATH" {
    default = "./keys/terraform_key.pem"
}

variable "VPC_CIDR" {
    default = "10.0.0.0/16"
}

variable "FIRST_SUBNET_CIDR" {
    default = "10.0.1.0/24"
}

variable "FIRST_DC_IP" {
    default = "10.0.1.101"
}

variable "SECOND_DC_IP" {
    default = "10.0.1.102"
}

variable "USER_SERVER_IP" {
  default = "10.0.1.50"
}

variable "ATTACK_SERVER_IP" {
  default = "10.0.1.10"
}

variable "PUBLIC_DNS" {
    default = "1.1.1.1"
}

variable "MANAGEMENT_IPS" {
    # Add in the public IP Address you will be hitting the cloud from, for example the public IP of your home address or VPN
    # default = ["1.2.3.4/32"]
}

variable "WINDOWS_SERVER_AMI" {
    default = "ami-051148891ab67c55e"
}

variable "DEBIAN_AMI" {
    default = "ami-03c5ca432499db74d"
}

variable "SSM_S3_BUCKET" {
    # Add in the name of your S3 bucket like the example below
    # default = "this-is-just-a-fake-bucket"
}

data "http" "ip" {
    url = "https://ifconfig.me/ip"
}

output "ip" {
    value = data.http.ip.response_body
}