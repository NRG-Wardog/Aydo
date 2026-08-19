# Security Policy

Aydo is an educational/research endpoint-security platform and contains privileged Windows components, malware-analysis workflows, backend services, and sandbox orchestration. Please treat security reports responsibly.

## Supported Branch

The actively published branch is `production`. Development may also occur on intermediate branches before promotion.

## Reporting a Vulnerability

Do **not** publish exploitable vulnerability details, credentials, malware samples, or sensitive host information in a public GitHub issue.

Report security-sensitive findings privately to the repository owner through the contact information on the GitHub profile. Include:

- affected component/path;
- concise reproduction conditions;
- expected vs. observed behavior;
- security impact;
- relevant logs or stack traces with secrets removed;
- a suggested remediation if available.

## Scope

Useful reports include issues such as:

- privilege-boundary mistakes between kernel and user mode;
- unsafe IPC or authorization behavior;
- path traversal or unsafe file handling;
- secret/credential exposure;
- backend authentication/authorization defects;
- unsafe sandbox lifecycle assumptions;
- denial-of-service conditions caused by malformed input;
- insecure update/configuration handling.

## Out of Scope

- reports that require intentionally disabling the documented security boundary or replacing trusted local configuration with a malicious one;
- social-engineering-only scenarios;
- claims based only on the fact that malware-analysis code executes samples inside a configured sandbox;
- attacks against third-party products or infrastructure not owned by this project.

## Malware Samples

Do not submit live malware binaries through public issues or pull requests. Use hashes, redacted metadata, or minimal non-malicious reproductions whenever possible.

## Disclosure

Please allow reasonable time for triage and remediation before public disclosure. Confirmed reports will be documented in release notes or security advisories when appropriate.
