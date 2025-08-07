# AWS Bootcamp – VM Creation with SEV Support

**Audience:** Technical Mentors (Experienced in Tech Industry)  
**Objective:** Learn AWS fundamentals, create an EC2 instance, and enable Secure Encrypted Virtualization (SEV) for Confidential Computing.

---

## 1. Introduction to AWS

### What is AWS?
Amazon Web Services (AWS) is a cloud platform offering 200+ services for compute, storage, networking, AI, and more.

### Why AWS?
- Scalability  
- Pay-as-you-go pricing  
- Global reach  
- Security

### AWS Global Infrastructure
- **Region** – Geographically separated AWS area (e.g., `us-east-1` in N. Virginia).
- **Availability Zone (AZ)** – Data center(s) within a region for redundancy.

**Significance of Region:** Selecting the right AWS region is important because it directly impacts your application's **performance, cost, data compliance, and availability**.

---

## 2. Core AWS Concepts

### 2.1 EC2 (Elastic Compute Cloud)
- Virtual servers in the cloud
- Flexible in terms of OS, CPU, RAM, storage
- Pricing models: On-Demand, Reserved, Spot Instances

### 2.2 Instance
- A virtual machine you run on AWS EC2
- Defined by **instance type** (CPU, RAM)
- Runs from an **AMI**

### 2.3 AMI (Amazon Machine Image)
- Blueprint for your instance
- Contains:
  - OS (e.g., Ubuntu, Amazon Linux)
  - Pre-installed software
  - Storage configuration

---

## 3. AWS Support for SEV

- SEV-enabled instance families:
  - General Purpose: `m6a`
  - Compute Optimized: `c6a`
  - Memory Optimized: `r6a`
- Availability: Only in certain AWS regions

---

## 4. Step-by-Step: Launching a SEV-enabled EC2 Instance

### Step 1: Login to AWS Console
- Go to [https://aws.amazon.com/console](https://aws.amazon.com/console)
- Sign in with your IAM account

### Step 2: Navigate to EC2 Service
- From AWS Console, search for **EC2**

### Step 3: Launch an Instance
- Click **Launch Instance**

### Step 4: Choose AMI
- Example: **Amazon Linux 2** or **Ubuntu 20.04**

### Step 5: Select Instance Type
- Choose a **SEV-supported type**: `m6a.large` or higher

### Step 6: Configure Instance
- VPC & Subnet selection
- IAM role (if needed)
- Keep **encryption at rest** enabled

### Step 7: Add Storage
- Default EBS volume is fine (keep encrypted)

### Step 8: Configure Security Group
- Allow **SSH (port 22)** from your IP
- Add other ports as needed

### Step 9: Create / Select Key Pair
- Download `.pem` key for SSH access

### Step 10: Launch Instance

---

## 5. Verifying SEV on the Instance

1. SSH into the instance:
   ```bash
   ssh -i your-key.pem ec2-user@your-public-ip
   ```
2. Check SEV flags:
   ```bash
   dmesg | grep -i sev
   lscpu | grep -i sev
   ```

---

## 6. Best Practices
- Always choose the **right region** for latency & compliance
- Use IAM roles instead of storing credentials on the instance
- Enable **CloudTrail** for logging
- Use **Systems Manager Session Manager** instead of SSH for extra security

---

## 7. Resources
- [AWS EC2 Documentation](https://docs.aws.amazon.com/ec2/)
- [AWS AMD SEV Overview](https://aws.amazon.com/ec2/amd/)
- [Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
