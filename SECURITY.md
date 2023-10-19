# Security Policy

## Security-critical bug reporting policy

For "security-critical" bugs we have a dedicated bug-reporting
process that is distinct from the main project's Github issue
tracker. Here, we define a bug as "security critical" if:

1. The bug can be used to disclose confidential data by a principal
   in a computation with another principal, where both principals
   belong to a security domain in a secure-enclave whose trust
   policy is managed by a Certifier Service instance.

2. This flow of information is not explicitly allowed by the global
   policy of a particular security-domain, or could be used to
   undermine any computation independent of the particular global
   policy in force.

3. Is not explicitly outside of the Certifier Framework's threat-model.

If you believe that you have found a bug in the Certifier Frameworks'
code-base that satisfies all of the conditions above, then please
report the issue discreetly and directly to the Certifier Framework's
development team, using the dedicated e-mail alias: certifier-framework@vmware.com.

Once reported, a member of the development team will engage with you to
further understand the bug and work on developing a fix for the
issue.

## Supported Versions

The Certifier Framework is in late-stage Beta development phase. No major releases are supported, yet.

## Reporting a Vulnerability

During the beta, please report vulnerabilities through this feedback process.
