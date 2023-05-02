# pkilint


[![PyPI](https://img.shields.io/pypi/v/pkilint.svg?maxAge=2592000)](https://pypi.org/project/pkilint)
[![Python Versions](https://img.shields.io/pypi/pyversions/pkilint.svg)](https://pypi.org/project/pkilint/)
[![Build status](https://github.com/digicert/pkilint/actions/workflows/build_and_publish.yml/badge.svg)](https://github.com/digicert/pkilint/actions/workflows/build_and_publish.yml)
[![GitHub license](https://img.shields.io/pypi/l/pkilint)](https://raw.githubusercontent.com/digicert/pkilint/main/LICENSE)

pkilint is a linting framework for documents that are encoded using ASN.1. pkilint is designed to
be a highly extensible toolbox to quickly create linters for a variety of ASN.1 structure/"document" types to check for compliance with
various standards and policies.

There are several ready-to-use command-line tools bundled with pkilint, or the API can be used to create new linters.

## Installation

1. Python 3.9 or newer must be installed. Python can be downloaded and installed from https://www.python.org/downloads/, or
use your operating system's package manager.

2. To ensure that package dependencies for pkilint do not conflict with globally installed packages on your machine, it is
recommended that you use [pipx](https://pypa.github.io/pipx/) to create a separate Python environment for pkilint. Follow
the instructions on the [pipx homepage](https://pypa.github.io/pipx/) to install pipx.

3. Use pipx to install pkilint:

    `pipx install pkilint`

Once installed, the bundled command line applications (listed below) and the API will be available on your machine.

## Usage

In addition to the API, several command line tools are bundled with pkilint. Upon termination of execution, each linter
will return the number of reported findings as the process exit code.

The list of command line linters bundled with pkilint:

* `lint_pkix_cert`
* `lint_cabf_smime_cert`
* `lint_cabf_servercert_cert`
* `lint_crl`
* `lint_ocsp_response`
* `lint_pkix_signer_signee_cert_chain`


Each of the linters share common command line parameters:

| Parameter         | Default value | Description                                                                                        |
|-------------------|---------------|----------------------------------------------------------------------------------------------------|
| `-s`/`--severity` | INFO          | Sets the severity threshold for findings. Findings that are below this threshold are not reported. |
| `-f`/`--format`   | TEXT          | Sets the format in which results will be reported. Current options are TEXT, CSV, or JSON.         |

Additionally, each linter has ability to lint document (certificate, CRL, OCSP response, etc.) files as well as output the set of validations
which are performed by each linter. When the `validations` sub-command is specified, the set of validations that are performed by the linter
is output to standard output in CSV format.

When the `lint` sub-command is specified for each linter, a file which contains the document to lint must be specified. The document
may be either DER- or PEM-encoded.

Each of the command line tools wrap various linter APIs available within pkilint. 

### lint_pkix_cert

This is the "base" X.509 certificate linter that lints specified certificates against RFC 5280 and related RFCs.

### lint_cabf_smime_cert

This tool lints end-entity S/MIME certificates against the
[CA/Browser Forum S/MIME Baseline Requirements](https://cabforum.org/smime-br/). 

The `lint` sub-command requires that the user provide the certificate type/profile of the certificate so that the appropriate
validations are performed. There are three options:

1. Explicitly specify the type of S/MIME certificate using the `-t`/`--type` option. This may be useful when linting S/MIME certificates where the policy OIDs in the certificate do not map to a S/MIME validation level and generation.
2. Have the linter detect the type of certificate using the `-d`/`--detect` option. In this case, the linter will determine the validation level and generation using the policy OIDs included in the certificate. If a reserved CA/Browser Forum policy OID is found, then the corresponding validation level and generation are used. If no such reserved OIDs are found, then the optional mapping file (see below) is used. If no OIDs in the mapping file are found, then the tool exits with an error.
3. Have the linter detect the type of certificate using the `-g`/`--guess` option. This option uses the same identification procedure as the `--detect` option, with one major difference. Instead of exiting with an error upon being unable to find an appropriate policy OID, this option instead directs the linter to use heuristics to determine the validation level and generation.

Options 2 and 3 allow for the use of an optional mapping file, specified using the `-m`/`--mapping` option. This file contains one or more mappings from policy OIDs to the corresponding validation level and generation.

For example, the following mapping file is used to map policy OID `1.2.3.4.5.6` to the `MAILBOX-LEGACY` validation level and generation and `1.2.3.4.5.7` to the `SPONSORED-LEGACY` validation level and generation:

~~~
1.2.3.4.5.6=MAILBOX-LEGACY
1.2.3.4.5.7=SPONSORED-LEGACY
~~~

The `-o`/`--output` option is used to specify that the validation level and generation used by the linter is written to standard error. This is useful when using the `--guess` option to see which validation level and generation was determined by the heuristics logic.

#### Example command execution

```shell
$ echo '-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIUOxQXk96tNHCeyZ9P3uUbIFT/fkAwDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0
ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MjgwMDAwMDBaFw0y
MzA3MjcyMzU5NTlaME4xIjAgBgNVBAMMGWhhbmFrby55YW1hZGFAZXhhbXBsZS5j
b20xKDAmBgkqhkiG9w0BCQEWGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw+egZQ6eumJKq3hfKfED4dE/t
L4FI5sjqont9ABVI+1GSqyi1bFBgsRjM0THllIdMbKmJtWwnKW8J+5OgNN8y6Xxv
8JmM/Y5vQt2lis0fqXmG8UTz0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY
7JRVcbB4khUN3Gp0yg+801SXzoFTTa+UGIRLE66jH51aa5VXu99hnv1OiH8tQrjd
i8mH6uG/icq4XuIeNWMF32wHqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSE
onWW4HtLbtmS8He1JNPc/n3dVUm+fM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTAgMB
AAGjggFnMIIBYzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSME
GDAWgBTWRAAyfKgN/6xPa2buta6bLMU4VDAdBgNVHQ4EFgQUiRlZXg7xafXLvUfh
NPzimMxpMJEwFAYDVR0gBA0wCzAJBgdngQwBBQEDMD0GA1UdHwQ2MDQwMqAwoC6G
LGh0dHA6Ly9jcmwuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYV9jcmwuY3JsMEsG
CCsGAQUFBwEBBD8wPTA7BggrBgEFBQcwAoYvaHR0cDovL3JlcG9zaXRvcnkuY2Eu
ZXhhbXBsZS5jb20vaXNzdWluZ19jYS5kZXIwEwYDVR0lBAwwCgYIKwYBBQUHAwQw
TAYDVR0RBEUwQ4EZaGFuYWtvLnlhbWFkYUBleGFtcGxlLmNvbaAmBggrBgEFBQcI
CaAaDBjlsbHnlLDoirHlrZBAZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggIB
AHnCKUIVRevmlvlmQ5wYe/mGJyQs/DxqqxMwkkkh/rjj57uEgcYGNojWGFV4D60z
CQhw6eXiQv5txPvbBEwCzfl21mw3ocEutA3b6AW/Si69PgLZpCK7wTha6k5LNdKt
IKyVoFO6rSQGRzpzmxVL6b7V5tDOvcn2gqgQMElSz7DmGo507yq4eY1HJLXX8H5O
zjfPer8wXrfgKoTXBbVy9Maqc3Sx4bJSr6o4xhljIS4vYKeXOh3e39TGWl0/rqqP
V0V6DCn33q59DkRDmcROVuApzo4gw60PQxIC5nMLGGOo1A28/YSQvXltzZUM3gZS
GsuRBYXPJ1N6ExrxbcnUaimRFQjKFbFmv1WETdGmxqswlHBXFw5xhS+OSPnp3W3Q
+hSanTPVVjnZmr+iyRBjYte6B/Z35FfLbtIcEGGG8v+1gTwMOnWsr4HzF7tLz9tC
+fzZb5RhXav/+soJ9duiyFydfeEvObo8vzyUhgQBlAq8kyoTcLkvZS7/PGbbsxE7
4HWrS6SFnWm8gHg5WK9r6VGU0HjE3cyKU1T4oZZGdZCBxC0CN0lnKzVSuE6A5ZXR
uDRUO4aTIxMwcLw8N6d/SrMM4/SuKV3mlGmhWdI+3g/d3QcTUTtZD24EzXypVOdu
5SGS04ZwcWyIe7mE1HadAVicrFfRg8KzCDpciGSatEz1
-----END CERTIFICATE-----' > smbr_cert_factory_mailbox_strict.pem

$ lint_cabf_smime_cert lint -d smbr_cert_factory_mailbox_strict.pem
SubjectKeyIdentifierValidator @ certificate.tbsCertificate.extensions.3.extnValue.subjectKeyIdentifier
    pkix.subject_key_identifier_method_1_identified (INFO)
    
$
```

### lint_cabf_servercert_cert

This tool lints TLS server authentication certificates and Issuing CA certificates against the
[CA/Browser Forum TLS Baseline Requirements](https://cabforum.org/baseline-requirements-documents/). This tool is still in its early stages in terms of the completeness of checks it performs. It is anticipated that this linter
will be updated to encompass the changes proposed in the [SC-62 Certificate Profiles Ballot](https://cabforum.org/2023/03/17/ballot-sc62v2-certificate-profiles-update/).

### lint_crl

This tool lints CRLs against the RFC 5280 as well as against the CA/Browser Forum profile for CRLs.

### lint_ocsp_response

This tool lints OCSP responses against the RFC 6960 profile.

### lint_pkix_signer_signee_cert_chain

This tool lints subject/issuer certificate pairs to ensure consistency of fields and extension values across certificates.

## Bugs?

If you find a bug or other issue with pkilint, please create a Github issue.

## Contributing

As we intend for this project to be an ecosystem resource, we welcome contributions. It is preferred that proposals for new
features be filed as Github issues so that design decisions, etc. can be discussed prior to submitting a pull request.

## Acknowledgements

pkilint is built on several open source packages. In particular, these packages are dependencies of this project:

| Name               | License                              | Author                                                         | URL                                               |
|--------------------|--------------------------------------|----------------------------------------------------------------|---------------------------------------------------|
| cryptography       | Apache Software License; BSD License | The Python Cryptographic Authority and individual contributors | https://github.com/pyca/cryptography              |
| iso3166            | MIT License                          | Mike Spindel                                                   | http://github.com/deactivated/python-iso3166      |
| publicsuffixlist   | Mozilla Public License 2.0 (MPL 2.0) | ko-zu                                                          | https://github.com/ko-zu/psl                      |
| pyasn1             | BSD License                          | Christian Heimes and Simon Pichugin                            | https://github.com/pyasn1/pyasn1                  |
| pyasn1-alt-modules | BSD License                          | Russ Housley                                                   | https://github.com/russhousley/pyasn1-alt-modules |
| python-dateutil    | Apache Software License; BSD License | Gustavo Niemeyer                                               | https://github.com/dateutil/dateutil              |
| PyYAML             | MIT License                          | Kirill Simonov                                                 | https://pyyaml.org/                               |
| validators         | MIT License                          | Konsta Vesterinen                                              | https://github.com/kvesteri/validators            |

The pkilint maintainers are grateful to the authors of these open source contributions.
