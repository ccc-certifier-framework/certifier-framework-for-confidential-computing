# AWS Bootcamp – Configuring an EC2 Instance

---

## 1. Introduction to AWS

### What is AWS?
Amazon Web Services (AWS) is a comprehensive cloud computing platform offering a wide range of services, including computing power, storage, networking, databases, analytics, and machine learning. AWS enables organizations and individuals to deploy applications and services without the need for physical hardware.

### Why Use AWS?
- **Cost Efficiency** – Pay only for the resources you use.
- **Scalability** – Easily scale resources up or down to meet demand.
- **Global Reach** – Deploy resources in multiple geographic regions.
- **Security** – Enterprise-grade security with compliance certifications.

---

## 2. Key AWS Concepts

- **Region** – A geographical area containing AWS data centers. Selecting the correct region can optimize performance, reduce costs, and ensure compliance with data regulations.
- **Availability Zone (AZ)** – One or more isolated data centers within a region, providing redundancy and fault tolerance.
- **Service** – An AWS feature or capability (e.g., EC2 for compute, S3 for storage).
- **EC2 (Elastic Compute Cloud)** – A service that provides resizable virtual servers.
- **Instance** – A single virtual server running on AWS EC2.
- **AMI (Amazon Machine Image)** – A pre-configured template containing an operating system and optional software, used to launch an EC2 instance.

---

## 3. Prerequisites

- An active AWS account ([Create one here](https://aws.amazon.com))
- A laptop or desktop computer with internet access
- For connection via terminal: basic familiarity with command-line tools (optional)

---

## 4. Step-by-Step: Launching a Standard EC2 Instance

**Objective:** Deploy a virtual server on AWS.

### Step 1: Log in to the AWS Management Console
1. Navigate to [AWS Console](https://aws.amazon.com/console)
2. Sign in using your AWS credentials.

### Step 2: Access the EC2 Service
1. In the search bar at the top of the AWS Console, type `EC2`.
2. Select **EC2** from the search results to access the EC2 dashboard.

### Step 3: Launch a New Instance
1. Click **Launch Instance**.
2. Under **Name and tags**, provide a descriptive name for your instance (e.g., `myCertifierServer`).

### Step 4: Select an AMI (Operating System)
- Recommended: **Amazon Linux 2 AMI** or **Ubuntu 20.04 LTS**.

### Step 5: Choose an Instance Type
- For initial testing and free-tier eligibility, select **t2.micro**.

### Step 6: Create a Key Pair (For Secure Login)
1. Under **Key pair (login)**, select **Create new key pair**.
2. Provide a name (e.g., `mykeypair`).
3. Choose file format:
   - **PEM** for macOS/Linux
   - **PPK** for Windows (PuTTY)
4. Download the file and store it securely — this is required for SSH access.

### Step 7: Configure Network Settings (Security Group)
1. Allow **SSH (port 22)** access from your IP address for secure terminal access.
2. If hosting a website, also allow **HTTP (port 80)** and **HTTPS (port 443)**.

### Step 8: Launch the Instance
- Review all configurations and click **Launch Instance**.
- Wait until the **Instance state** changes to **Running**.

---

## 5. Connecting to Your Instance

### Locate the Public IP Address
1. From the EC2 dashboard, select your instance.
2. Under **Details**, locate the **Public IPv4 address**.

### macOS/Linux Connection
```bash
chmod 400 mykeypair.pem
ssh -i mykeypair.pem ec2-user@<YourPublicIP>
```
*(Replace `<YourPublicIP>` with your instance’s public IP address)*

### Windows Connection
- Convert `.pem` to `.ppk` using PuTTYgen.
- Open PuTTY, enter your instance’s public IP, and configure the private key in the **SSH > Auth** section.
- Click **Open** to initiate the connection.

---

## 6. Managing Your Instance
- **Stop** – Powers off the instance without deleting it (no compute charges while stopped).
- **Start** – Powers the instance back on.
- **Terminate** – Permanently deletes the instance.

---

## 7. Advanced Topic: Secure Encrypted Virtualization (SEV)

### Overview
SEV (Secure Encrypted Virtualization) is an AMD technology that encrypts the memory of an EC2 instance, ensuring that even the hypervisor cannot access it. This feature is part of AWS’s Confidential Computing offerings.

### Benefits of SEV
- Enhanced data security during processing
- Protection against unauthorized access, even from privileged system components
- Ideal for industries with strict compliance requirements, such as finance and healthcare

### Launching an SEV-Enabled Instance
1. Follow the same procedure as launching a standard EC2 instance.
2. In **Step 5 (Choose Instance Type)**, select an AMD SEV-compatible instance type:
   - General Purpose: `m6a`
   - Compute Optimized: `c6a`
   - Memory Optimized: `r6a`

### Verifying SEV in Your Instance
Once connected via SSH, run:
```bash
dmesg | grep -i sev
lscpu | grep -i sev
```
If SEV is enabled, references to SEV will appear in the output.

---

## 8. Best Practices
- Choose the AWS Region closest to your users for optimal latency and compliance.
- Secure AWS credentials and enable MFA.
- Stop or terminate unused instances to avoid unnecessary charges.
- Use IAM roles rather than embedding credentials in applications.

---

## 9. References
- [AWS EC2 Documentation](https://docs.aws.amazon.com/ec2/)
- [AWS Free Tier Information](https://aws.amazon.com/free)
- [AWS AMD SEV Overview](https://aws.amazon.com/ec2/amd/)
