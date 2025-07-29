# Terraform IaC Security Scanning with Checkov

This project demonstrates **Infrastructure as Code (IaC) security scanning** using **Terraform** and **Checkov**.
It includes an intentionally insecure Terraform configuration (`main.tf`) and a remediated secure version (`main_fixed.tf`).

The project highlights **common cloud security misconfigurations** in AWS resources (S3, EC2, IAM, Security Groups, EBS) and how to remediate them.

## How It Works

1. **Run Checkov against `main.tf`**
   - Detects insecure configurations.
   - Produces a list of failed security checks.

2. **Create a remediated version `main_fixed.tf`**
   - Fixes key security issues.
   - Re-run Checkov to verify improvements.

3. **Document findings and decisions**
   - Some optional checks are intentionally skipped for simplicity.

## Remediated Resources

| Resource | Key Security Fixes |
|----------|---------------------|
| **S3 Bucket (secure_bucket)** | Made private, added versioning, encryption (KMS), access logging, lifecycle rule, replication, event notifications |
| **Security Group** | Restricted ingress to specific IP, added descriptions, limited outbound traffic |
| **IAM Policy** | Removed wildcard actions/resources, limited to least privilege (s3:GetObject, s3:ListBucket) |
| **EBS Volume** | Enabled encryption using a **customer-managed KMS key (CMK)** |
| **EC2 Instance** | Removed public IP, enabled IMDSv2, encrypted root volume, enabled monitoring, attached IAM role |

## Checkov Results

### Before (main.tf)

- 30+ failed checks including:
  - Public S3 bucket with no encryption/versioning.
  - Security group allowing 0.0.0.0/0 on all ports.
  - IAM policy with Action="*" and Resource="*".
  - Unencrypted EBS volume and EC2 root volume.
  - No IAM role attached to EC2 instance.

### After (main_fixed.tf)

Most high-impact findings are fixed, including:
- IAM least privilege
- EBS encryption with CMK
- EC2 security hardening
- Secure S3 bucket configuration

### Mapping of Findings to Fixes

| Check ID | Issue | Remediation |
|----------|-------|-------------|
| CKV_AWS_20 | S3 bucket public ACL | Changed ACL to private, added public access block |
| CKV_AWS_21 | No versioning on S3 bucket | Added versioning block |
| CKV_AWS_145 | No encryption | Added server-side encryption with KMS |
| CKV_AWS_18 | No access logging | Added logging to a dedicated log bucket |
| CKV2_AWS_61 | No lifecycle configuration | Added lifecycle rule for storage class transition |
| CKV_AWS_260/24/25/277 | Security group allows 0.0.0.0/0 | Restricted ingress to a specific IP |
| CKV_AWS_23 | Missing SG rule description | Added descriptions to ingress/egress rules |
| CKV_AWS_288/289/290/287/63/62/355/286 | IAM policy allows "*" actions/resources | Replaced with least privilege policy (GetObject/ListBucket) |
| CKV_AWS_189 | EBS not encrypted with CMK | Created KMS key and referenced it in EBS volume |
| CKV_AWS_3/8 | Unencrypted EC2 root volume | Enabled encryption in root_block_device |
| CKV_AWS_79 | IMDSv1 enabled | Configured metadata_options to require tokens |
| CKV_AWS_88 | Public IP assigned | Set associate_public_ip_address to false |
| CKV_AWS_126 | Detailed monitoring disabled | Enabled monitoring = true |
| CKV_AWS_135 | EC2 not EBS optimized | Set ebs_optimized = true |
| CKV2_AWS_41 | No IAM role attached | Created IAM role and instance profile for EC2 |
| CKV_AWS_144 | No replication | Configured cross-region replication for main bucket |

## Remaining Failed Checks (and Why)

| Check ID | Resource | Reason Skipped |
|----------|----------|----------------|
| CKV_AWS_18 | log_bucket, replica_bucket | Log and replica buckets lack access logging to avoid adding more nested buckets just for logging. |
| CKV2_AWS_61 | log_bucket, replica_bucket | No lifecycle rules for these buckets to keep code minimal. |
| CKV2_AWS_62 | log_bucket, replica_bucket | No event notifications on these buckets to avoid adding more SNS/Lambda resources. |
| CKV_AWS_145 | log_bucket | Uses AES256 encryption instead of KMS CMK to avoid another key resource. |
| CKV_AWS_144 | All S3 buckets | Cross-region replication is configured only for the main bucket. Replicating log and replica buckets would add significant complexity. |

## Why Some Checks Were Skipped

This project is designed to demonstrate common IaC security issues and their remediation without making the Terraform code overly complex.

- Adding logging for log buckets requires another dedicated bucket.
- Adding replication for every bucket would double or triple the code size.
- Event notifications for log/replica buckets add new SNS/Lambda resources without security value for this demo.

Instead, we fully hardened the main bucket and other critical resources while acknowledging trade-offs in the README.

## How to Run

### Install Checkov
```
pip install checkov
```

### Scan Insecure Code
```
checkov -f main.tf
```

### Scan Remediated Code
```
checkov -f main_fixed.tf
```

## Key Takeaways

- Checkov quickly detects common IaC misconfigurations.
- Terraform code can be incrementally improved.
- Security best practices (least privilege, encryption, replication) can be automated.
- Real-world IaC remediation often involves trade offs between security and code complexity.
