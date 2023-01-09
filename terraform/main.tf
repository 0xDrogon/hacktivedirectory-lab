terraform {
    required_providers {
        aws = {
            source  = "hashicorp/aws"
            version = "~> 4.16"
        }
    }

    required_version = ">= 1.2.0"
}

provider "aws" {
    region     = "eu-west-1"
    access_key = file(var.aws_access_key)
    secret_key = file(var.aws_secret_key)
}

resource "aws_instance" "windows_server" {
    ami           = "ami-0142f1ad576b2cc4d"
    instance_type = "t2.small"

    tags = {
        Name = "WindowsServer"
    }
}