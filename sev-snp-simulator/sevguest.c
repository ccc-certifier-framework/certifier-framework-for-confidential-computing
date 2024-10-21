// SPDX-License-Identifier: GPL-2.0-only
// Based on AMD sev-guest driver
/*
 * AMD Secure Encrypted Virtualization Nested Paging (SEV-SNP) guest request
 * interface
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#define pr_fmt(fmt) "SNP: GUEST: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/set_memory.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>

#include "sevguest.h"
#include "sev-guest.h"
#include "attestation.h"
#include "snp-derive-key.h"

#define DEVICE_NAME "sev-guest"
#define AAD_LEN     48
#define MSG_HDR_VER 1

static unsigned int          sev_major = 0;
static struct class *        sev_class = NULL;
static struct snp_guest_dev *snp_dev = NULL;
;


/*
  From a real Sev machine

    Version: 2
    Guest SVN: 0
  Policy: 0x30000
    - Debugging Allowed:       No
    - Migration Agent Allowed: No
    - SMT Allowed:             Yes
    - Min. ABI Major:          0
    - Min. ABI Minor:          0
  Family ID:
    00000000000000000000000000000000
  Image ID:
    00000000000000000000000000000000
  VMPL: 0
  Signature Algorithm: 1 (ECDSA P-384 with SHA-384)
  Platform Version: 03000000000008115
    - Boot Loader SVN:   3
    - TEE SVN:           0
    - SNP firmware SVN:  8
    - Microcode SVN:    115
  Platform Info: 0x3
    - SMT Enabled: Yes
  Author Key Enabled: Yes
    Report Data:
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
  Measurement:
    5c19d5b4a50066c8c991bd920dfa2276e11d3531c91434a7
    34f3b258ab279cd1b3bbe89ef930236af11dc3d28c70f406
  Host Data:
    0000000000000000000000000000000000000000000000000000000000000000
  ID Key Digest:
    000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000
  Author Key Digest:
    000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000
  Report ID:
    e2af014dad028f1f2adf3c1b0f896a4e43307596fc75b9242c706764d82e620d
  Migration Agent Report ID:
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  Reported TCB: 03000000000008115
  - Boot Loader SVN:   3
  - TEE SVN:           0
  - SNP firmware SVN:  8
  - Microcode SVN:    115
  Chip ID:
    d30d7b8575881faa90edf4fb4f7a1c52a0beedef9321af3780abd4b4c16cf5c8
    132d9d15d6537f3704de10afe7e8d989c7959654c38be1905cf9506ea737976f
 */
// Note setting in get report too
static struct attestation_report default_report = {
    .version = 2,
    .guest_svn = 1,
    .policy = 0x00000ULL,  // no migrate, debug or SMT
    .signature_algo = SIG_ALGO_ECDSA_P384_SHA384,
    .platform_info = 0,  // SMT disable --- should be 0x03?
    // Hardcoded measurement
    .measurement =
        {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        },
};

/* SNP Guest message request */
struct snp_req_data {
  unsigned long req_gpa;
  unsigned long resp_gpa;
  unsigned long data_gpa;
  unsigned int  data_npages;
};

struct snp_guest_crypto {
  struct crypto_aead *tfm;
  u8 *                iv, *authtag;
  int                 iv_len, a_len;
};

struct snp_guest_dev {
  struct cdev       cdev;
  struct device *   dev;
  struct miscdevice misc;

  void *                          certs_data;
  struct snp_guest_crypto *       crypto;
  struct snp_guest_msg *          request, *response;
  struct snp_secrets_page_layout *layout;
  struct snp_req_data             input;
  u32 *                           os_area_msg_seqno;
  u8 *                            vmpck;
};

/* Mutex to serialize the shared buffer access and command handling. */
static DEFINE_MUTEX(snp_cmd_mutex);

static int get_report(struct snp_guest_dev *          snp_dev,
                      struct snp_guest_request_ioctl *arg) {
  struct snp_report_req   req;
  int                     rc = 0;
  struct msg_report_resp *report_resp;

  default_report.reported_tcb.raw = 0x03000000000008115ULL;
  default_report.platform_version.raw = 0x03000000000008115ULL;
  lockdep_assert_held(&snp_cmd_mutex);

  if (!arg->req_data || !arg->resp_data)
    return -EINVAL;

  if (copy_from_user(&req, (void __user *)arg->req_data, sizeof(req)))
    return -EFAULT;

  report_resp = kzalloc(sizeof(*report_resp), GFP_KERNEL_ACCOUNT);
  if (!report_resp)
    return -ENOMEM;

  // Composing dummy report
  memcpy(&report_resp->report, &default_report, sizeof(default_report));
  report_resp->report.vmpl = req.vmpl;
  memcpy(report_resp->report.report_data, req.user_data, sizeof(req.user_data));

  report_resp->status = 0;
  report_resp->report_size = sizeof(report_resp->report);

  if (copy_to_user((void __user *)arg->resp_data,
                   report_resp,
                   sizeof(*report_resp)))
    rc = -EFAULT;

  arg->fw_err = 0;

  kfree(report_resp);
  return rc;
}

static int get_derived_key(struct snp_guest_dev *          snp_dev,
                           struct snp_guest_request_ioctl *arg) {
  struct snp_derived_key_resp resp;
  struct snp_derived_key_req  req;
  struct msg_key_resp *       key_resp = (struct msg_key_resp *)&resp.data;
  int                         rc = 0;
  u8 buf[32] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  lockdep_assert_held(&snp_cmd_mutex);

  if (!arg->req_data || !arg->resp_data)
    return -EINVAL;

  if (copy_from_user(&req, (void __user *)arg->req_data, sizeof(req)))
    return -EFAULT;

  // TODO: Compose key. For now, only handle root key and measurement mix
  if (req.root_key_select) {
    // Use VMRK? Just set the first bit
    buf[0] |= 0x80;
  } else {
    buf[0] &= 0x7F;
  }
  if (req.guest_field_select & FIELD_MEASUREMENT_MASK) {
    memcpy(&buf[16], default_report.measurement, 16);
  }

  key_resp->status = 0;

  memcpy(key_resp->derived_key, buf, sizeof(buf));
  if (copy_to_user((void __user *)arg->resp_data, &resp, sizeof(resp)))
    rc = -EFAULT;

  arg->fw_err = 0;

  return rc;
}

static int get_ext_report(struct snp_guest_dev *          snp_dev,
                          struct snp_guest_request_ioctl *arg) {
  printk(KERN_WARNING "SEV Guest Null driver get_ext_report\n");
  return -1;
}

static long snp_guest_ioctl(struct file * file,
                            unsigned int  ioctl,
                            unsigned long arg) {
  struct snp_guest_dev *snp_dev = (struct snp_guest_dev *)file->private_data;
  void __user *                  argp = (void __user *)arg;
  struct snp_guest_request_ioctl input;
  int                            ret = -ENOTTY;

  if (copy_from_user(&input, argp, sizeof(input)))
    return -EFAULT;

  input.fw_err = 0xff;

  mutex_lock(&snp_cmd_mutex);

  switch (ioctl) {
    case SNP_GET_REPORT:
      ret = get_report(snp_dev, &input);
      break;
    case SNP_GET_DERIVED_KEY:
      ret = get_derived_key(snp_dev, &input);
      break;
    case SNP_GET_EXT_REPORT:
      ret = get_ext_report(snp_dev, &input);
      break;
    default:
      break;
  }

  mutex_unlock(&snp_cmd_mutex);

  if (input.fw_err && copy_to_user(argp, &input, sizeof(input)))
    return -EFAULT;

  return ret;
}

static int snp_guest_open(struct inode *inode, struct file *file) {
  unsigned int smajor = imajor(inode);
  unsigned int sminor = iminor(inode);

  struct snp_guest_dev *dev = NULL;

  if (smajor != sev_major || sminor != 0) {
    printk(KERN_WARNING "No device found with minor=%d and major=%d\n",
           smajor,
           sminor);
    return -ENODEV;
  }

  dev = snp_dev;
  file->private_data = dev;

  if (inode->i_cdev != &dev->cdev) {
    printk(KERN_WARNING "open failed\n");
    return -ENODEV; /* No such device */
  }

  printk(KERN_WARNING "SEV Guest Null driver opened\n");
  return 0;
}

static const struct file_operations snp_guest_fops = {
    .owner = THIS_MODULE,
    .open = snp_guest_open,
    .unlocked_ioctl = snp_guest_ioctl,
};

static int construct_device(struct snp_guest_dev *dev, struct class *class) {
  int            err = 0;
  dev_t          devno = MKDEV(sev_major, 0);
  struct device *device = NULL;

  BUG_ON(dev == NULL || class == NULL);

  cdev_init(&dev->cdev, &snp_guest_fops);
  dev->cdev.owner = THIS_MODULE;

  err = cdev_add(&dev->cdev, devno, 1);
  if (err) {
    printk(KERN_WARNING "Error %d while trying to add %s", err, DEVICE_NAME);
    return err;
  }

  device = device_create(class,
                         NULL, /* no parent device */
                         devno,
                         NULL, /* no additional data */
                         DEVICE_NAME);
  dev->dev = device;

  if (IS_ERR(device)) {
    err = PTR_ERR(device);
    printk(KERN_WARNING "Error %d while trying to create %s", err, DEVICE_NAME);
    cdev_del(&dev->cdev);
    return err;
  }
  return 0;
}

static void sev_guest_cleanup_module(void) {
  /* Get rid of character devices (if any exist) */
  if (snp_dev) {
    device_destroy(sev_class, MKDEV(sev_major, 0));
    cdev_del(&snp_dev->cdev);
    kfree(snp_dev);
  }

  if (sev_class)
    class_destroy(sev_class);

  unregister_chrdev_region(MKDEV(sev_major, 0), 1);
  return;
}

static int __init sev_guest_init_module(void) {
  int   err = 0;
  dev_t dev = 0;

  err = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
  if (err < 0) {
    printk(KERN_WARNING "alloc_chrdev_region() failed\n");
    return err;
  }
  sev_major = MAJOR(dev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
  sev_class = class_create(THIS_MODULE, DEVICE_NAME);
#else
  sev_class = class_create(DEVICE_NAME);
#endif
  if (IS_ERR(sev_class)) {
    err = PTR_ERR(sev_class);
    goto fail;
  }

  snp_dev =
      (struct snp_guest_dev *)kzalloc(sizeof(struct snp_guest_dev), GFP_KERNEL);
  if (snp_dev == NULL) {
    err = -ENOMEM;
    goto fail;
  }
  /* Construct devices */
  err = construct_device(snp_dev, sev_class);
  if (err) {
    goto fail;
  }

  printk(KERN_WARNING "SEV Guest Null Driver Loaded");
  return 0; /* success */

fail:
  sev_guest_cleanup_module();
  return err;
}

static void __exit sev_guest_exit_module(void) {
  sev_guest_cleanup_module();
  printk(KERN_WARNING "SEV Guest Null Driver Removed");
  return;
}

module_init(sev_guest_init_module);
module_exit(sev_guest_exit_module);

MODULE_AUTHOR("Ye Li <yel@vmware.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("AMD SNP Mockup Guest Driver");
