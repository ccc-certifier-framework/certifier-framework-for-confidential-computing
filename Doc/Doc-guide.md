# Documentation Guide

The documentation is organized as follows.

## General Description

"RepositoryWhitepaper.[docx, pdf]" and "Guide.[docx, pdf] in the "Doc" directory are introductions to the Certifier Framewok.  These documents
are a good place to start, even if you just scan them.  Similarly, "INSTALL.md" and "README.md" in the top level directory covers
the over all structure of this repository including the important "sample_apps" which show developers how to use the Certifier Library
as well as the optional libraries.  Using the Certification server ("simpleserver") is best explained by studying the sample_apps and,
in general, the sample_apps are the best detailed source of informition on the API.

## Developer Documents

The documents in the "development_notes" should be of use to prospective developers.  Here is a brief description of those documents:

"developer_tour.md" is a brief tour from a development and deployment perspective of using the Certifier Framework.
Developers should start here.

"short-api-guide.md" is an abbreviated description of the Certifier API although it covers most of the basics.  For someone
building programs or utilities using the Certifier, this is a good second stop.  This is based on the most recent API version.

"APP-RUNTIME-STRUCTURE.md" is a more in-depth explanation of the sample apps and can be used as a guide as you develop your
first applications.

"instructions.md" in the top level "app_lib" directory describes the granular access prototype that used the Certifier.

"install-certifier-Ubuntu-20.04.md" has a description (written early) on installing the Certifier Framework in an Ubuntu OS, the AWS documents
below are more recent.

"aws_install.md" and "AWS-documentation.md" explain hpow to install the Certifier Framework in AWS intances.

"python_bindings.md" describes the python binding.

The certifier now contains a number of utilities to support VM based enclaves.  These do not require writing additional code
but are good examples.  The descriptions are in "vm_model_tools/cf_utility_usage_notes.md" as well as the instructions in
"vm_model_tools/examples/scenarios1."  INstructions on building these tools are in ""vm_model_tools/src."

The remaining documents are specialized and are not of general interest, they include:
SevProvisioning.[docx, pdf], Certifier-Nvidia-H100GPU-Support.[docx,pdf], 
Directory-structure-for-examples-and-deployment-guide.docx and tdx_design_note.md.

## Presentations

The "Presentation" directory has a series of presentations we've done on the Certifier.

## Platform Documents

This contains some supporting platform documents.  Most people will not need to look at this.
