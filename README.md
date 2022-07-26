# Certifier Framework for Confidential Computing

## Overview

The Certifier Framework for Confidential Computing consists of a client API
called the certifier API and server based policy evaluation server called
the Certifier Service.

The Certifier API greatly simplifies and unifies programming and
operations support for multi-vendor Confidential Computing platforms
by providing simple client trust management including attestation evaluation,
secure storage, platform initialization, secret sharing, secure channels
and other services.

The Certifier Service provides support for scalable, policy driven
trust management including attestation evaluation, application upgrade
and other Confidential Computing Trust services.

This project was started at the VMware Inc.

Except as expressly noted in individual source files, the code and
accompanying material is licensed for general use under the Apache
2.0 License. Some test drivers are licensed under GPL 2.0; fortunately,
there are very few affected files and none of the GPL code is
required in the certifier API, sample applications, utilities or
the Certifier Service.

Please consult the LICENSE file for APACHE 2.0 details and terms.
By using this software you agree to those terms of the respective licenses.

The repository contains the complete Certifier Framework source and a number of
examples as well as complete instructions.  In particular, the sample in
sample_app policy is a complete guide on building
and application, policy and deploying a service.

## Documentation and Installation

Instructions on building the Certifier Framework for Confidential Computing can
be found in INSTALL.md and additional documentation can be found in the Doc
subdirectory.

## Feedback and questions

Feedback and questions can be submitted on the github site.  All feedback will be
treated as licensed under the Apache license.

## Contributing

The certifier-framework-for-confidential-computing project team welcomes contributions from the
community. Before you start working with certifier-framework-for-confidential-computing, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Except as expressly set forth in a source file, the contents of this repository are licensed
under the Apache 2.0 license which is included in the LICENSE file.  There are a very few files,
used for testing (and not included in the API or services) that have other license terms.

