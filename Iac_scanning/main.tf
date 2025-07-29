provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "demo-insecure-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "insecure_sg" {
  name   = "allow_all"
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "insecure_policy" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

variable "db_password" {
  default = "SuperSecret123"
}

resource "aws_ebs_volume" "insecure_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

resource "aws_instance" "insecure_instance" {
  ami                         = "ami-123456"
  instance_type               = "t2.micro"
  associate_public_ip_address = true
}
