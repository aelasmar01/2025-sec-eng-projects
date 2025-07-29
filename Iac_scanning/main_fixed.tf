provider "aws" {
  region  = "us-east-1"
  version = "~> 5.0"
}

provider "aws" {
  alias  = "replica"
  region = "us-west-2"
}

# KMS Key for EBS Encryption
resource "aws_kms_key" "ebs_key" {
  description             = "CMK for EBS volume encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  # Added minimal key policy to avoid CKV2_AWS_64
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action    = "kms:*",
        Resource  = "*"
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

# Log Bucket for S3 Access Logging
resource "aws_s3_bucket" "log_bucket" {
  bucket = "demo-log-bucket"
  acl    = "log-delivery-write"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning { enabled = true }
}

resource "aws_s3_bucket_public_access_block" "log_bucket_block" {
  bucket                  = aws_s3_bucket.log_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Main Secure S3 Bucket (Fully Hardened)
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "demo-secure-bucket"
  acl    = "private"

  versioning { enabled = true }

  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "main-bucket-logs/"
  }

  lifecycle_rule {
    id      = "transition-to-IA"
    enabled = true
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket_block" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SNS Topic for Notifications
resource "aws_sns_topic" "bucket_events" {
  name              = "bucket-events"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.secure_bucket.id
  topic {
    topic_arn = aws_sns_topic.bucket_events.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

# Replica Bucket (Simplified – Will trigger some Checkov warnings intentionally)
resource "aws_s3_bucket" "replica_bucket" {
  bucket   = "demo-secure-bucket-replica"
  acl      = "private"
  provider = aws.replica

  versioning { enabled = true }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "replica_bucket_block" {
  bucket                  = aws_s3_bucket.replica_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM Role for Replication
resource "aws_iam_role" "replication_role" {
  name = "s3-replication-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "s3.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "replication_policy" {
  name = "s3-replication-policy"
  role = aws_iam_role.replication_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:GetReplicationConfiguration", "s3:ListBucket"],
        Resource = [aws_s3_bucket.secure_bucket.arn]
      },
      {
        Effect   = "Allow",
        Action   = ["s3:GetObjectVersion", "s3:GetObjectVersionAcl"],
        Resource = ["${aws_s3_bucket.secure_bucket.arn}/*"]
      },
      {
        Effect   = "Allow",
        Action   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
        Resource = ["${aws_s3_bucket.replica_bucket.arn}/*"]
      }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "replication" {
  bucket = aws_s3_bucket.secure_bucket.id
  role   = aws_iam_role.replication_role.arn

  rules {
    id     = "replication"
    status = "Enabled"
    destination {
      bucket        = aws_s3_bucket.replica_bucket.arn
      storage_class = "STANDARD"
    }
  }
}

# Secure Security Group
resource "aws_security_group" "secure_sg" {
  name        = "restricted_sg"
  description = "Allow SSH only from admin IP"

  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.10/32"]
  }

  egress {
    description = "Allow outbound HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Least Privilege IAM Policy
resource "aws_iam_policy" "secure_policy" {
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["s3:GetObject", "s3:ListBucket"],
      Resource = [
        aws_s3_bucket.secure_bucket.arn,
        "${aws_s3_bucket.secure_bucket.arn}/*"
      ]
    }]
  })
}

# EBS Volume with CMK
resource "aws_ebs_volume" "secure_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs_key.arn
}

# IAM Role for EC2
resource "aws_iam_role" "ec2_role" {
  name = "ec2-secure-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "secure_profile" {
  name = "secure-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# Secure EC2 Instance
resource "aws_instance" "secure_instance" {
  ami                         = "ami-123456"
  instance_type               = "t2.micro"
  associate_public_ip_address = false
  monitoring                  = true
  ebs_optimized               = true
  iam_instance_profile        = aws_iam_instance_profile.secure_profile.name
  vpc_security_group_ids      = [aws_security_group.secure_sg.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted  = true
    kms_key_id = aws_kms_key.ebs_key.arn
  }
}
