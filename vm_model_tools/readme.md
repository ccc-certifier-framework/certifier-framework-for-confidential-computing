This directory contains additional tools and libraries to make a newly supported
security model easy to implement using the Certifier.  We call this the VM
OS security model.

The VM OS security model focues on protecting a VM. In this case,
the Certifier Framework provides certification and key services for an
VM in a security domain but policy enforcement is the sole responsibility
of the OS and its configuration.

Note that since the OS configuration, including trusted storage (using,
for example, dmverity or dmcrypt) are critical to the security model,
it is important that they be included in the attested measurement of
the OS. As a result, we are switching to more flexible measurement
tools.  For SEV-SNP, we use virtee, you can download this from
https://github.com/virtee/sev-snp-measure; there is some documantation in
https://github.com/virtee.  As an illustration of additional properties
included in an SEV measurement, we can include, the following flags
to taylor what we want to measure in the virtee tool:
  --ovmf PATH           OVMF file to calculate hash from
  --kernel PATH         Kernel file to calculate hash from
  --initrd PATH         Initrd file to calculate hash from (use with --kernel)
  --append CMDLINE      Kernel command line to calculate hash from (use with --kernel)

A description of the VM OS security model is described in osmodel_readme.md
in this directory.  To facilitate the use of VM OS security model, we
provide a new command line tools called cf_utility.  See the file 
cf_utility_usage_notes.md for a description of this utility.  The source
code for this utility is in ./src which includes build instructions in
build_readme.me.  There are examples on the use of cf_utility in subdirectories
under examples.  Each example is accompanied by a detailed script which
can be "copied and pasted" to illustrate each step of use.
