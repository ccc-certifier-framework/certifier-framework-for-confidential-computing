[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8912/badge)](https://www.bestpractices.dev/projects/8912)
# Certifier Framework for Confidential Computing

## Overview

The Certifier Framework for Confidential Computing consists of a client API
called the Certifier API and server-based policy evaluation server called
the Certifier Service.

The Certifier API greatly simplifies and unifies programming and
operations support for multi-vendor Confidential Computing platforms
by providing simple client trust management, including attestation evaluation,
secure storage, platform initialization, secret sharing, secure channels
and other services.

The Certifier Service provides support for scalable, policy-driven
trust management, including attestation evaluation, application upgrade
and other Confidential Computing Trust services.

This project was started at VMware Inc.

Except as expressly noted in individual source files, the code and
accompanying material is licensed for general use under the Apache
2.0 License. Some test drivers are licensed under GPL 2.0; fortunately,
there are very few affected files and none of the GPL code is
required in the Certifier API, sample applications, utilities or
the Certifier Service.

Please consult the LICENSE file for APACHE 2.0 details and terms.
By using this software you agree to those terms of the respective
licenses.

The repository contains the complete Certifier Framework source and a number of
examples as well as complete instructions.  In particular, the sample program
in [sample_apps/common/example_app.cc](./sample_apps/common/example_app.cc)
is a complete guide for building and developing an application, and
policy, as well as deploying a service.

## Documentation and Installation

Instructions on building the Certifier Framework for Confidential Computing can
be found in [INSTALL.md](INSTALL.md) and additional documentation can be found
in the Doc subdirectory.

## Feedback and questions

Feedback and questions can be submitted on the github site.  All feedback will be
treated as licensed under the Apache license.

## Contributing

The certifier-framework-for-confidential-computing project team welcomes
contributions from the community. Before you start working with this project
please read and sign our Contributor License Agreement
(https://cla.vmware.com/cla/1/preview). If you wish to contribute code
and you have not signed our Contributor Licence Agreement (CLA), our bot
will prompt you to do so when you open a Pull Request. For any questions about
the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).


## License

Except as expressly set forth in a source file, the contents of this repository
are licensed under the Apache 2.0 license which is included in the LICENSE
file.  There are a very few files, used for testing (and not included in
the API or services) that have other license terms.

