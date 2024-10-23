# pkilint


[![PyPI](https://img.shields.io/pypi/v/pkilint)](https://pypi.org/project/pkilint)
[![Python Versions](https://img.shields.io/pypi/pyversions/pkilint)](https://pypi.org/project/pkilint/)
[![Build status](https://github.com/digicert/pkilint/actions/workflows/build_and_publish.yml/badge.svg)](https://github.com/digicert/pkilint/actions/workflows/build_and_publish.yml)
[![GitHub license](https://img.shields.io/pypi/l/pkilint)](https://raw.githubusercontent.com/digicert/pkilint/main/LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

pkilint is a linting framework for documents that are encoded using ASN.1. pkilint is designed to
be a highly extensible toolbox to quickly create linters for a variety of ASN.1 structure/"document" types to check for compliance with
various standards and policies.

There are several ready-to-use command-line tools bundled with pkilint, or the Python API can be used to create new linters.

## Installation

### Installing locally

1. Python 3.9 or newer must be installed. Python can be downloaded and installed from https://www.python.org/downloads/, or
use your operating system's package manager.

2. To ensure that package dependencies for pkilint do not conflict with globally installed packages on your machine, it is
recommended that you use [pipx](https://pypa.github.io/pipx/) to create a separate Python environment for pkilint. Follow
the instructions on the [pipx homepage](https://pypa.github.io/pipx/) to install pipx.

3. Use pipx to install pkilint:

    ```shell
    pipx install pkilint
    ```

Once installed, the bundled command line applications (listed below) and the Python API will be available on your machine.

#### Upgrading

When a new version of pkilint is released, run the following command to upgrade your installation:

```shell
pipx upgrade pkilint
```

#### REST API Installation

pkilint provides a REST API component that can be installed as a package extra. The REST API is implemented as an ASGI
web application, so you will need to install an ASGI server in addition to the package extra. There are several ASGI
servers available; [Uvicorn](https://www.uvicorn.org/) has been confirmed to work well with the REST API application.

To install the REST API component and Uvicorn ASGI server using pipx, run the following commands:

```shell
pipx install pkilint[rest]
pipx inject pkilint --include-apps uvicorn
```

### Docker

Starting with v0.9.4, Docker images are provided with each release. In addition to the pkilint Python package, the image includes
[Uvicorn](https://www.uvicorn.org/) and [Gunicorn](https://gunicorn.org/). These additional packages allow the Docker image to be
readily used to run a server that provides the pkilint REST API.

To pull the latest version of the Docker image, execute the following command:

```shell
docker pull ghcr.io/digicert/pkilint
```

After the Docker image has been pulled, all command-line linters are available, as well as the Uvicorn and Gunicorn commands to start the
REST API server.

A few examples demonstrating use of the Docker image are provided below.

#### Linting an S/MIME certificate

```shell
$ echo '-----BEGIN CERTIFICATE-----
MIIF1DCCA7ygAwIBAgIUI+v/jTtadau/a5lLVGP50z0FoW8wDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0
ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0y
MzA3MTgyMzU5NTlaMEIxFjAUBgNVBAMMDVlBTUFEQSBIYW5ha28xKDAmBgkqhkiG
9w0BCQEWGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCw+egZQ6eumJKq3hfKfED4dE/tL4FI5sjqont9ABVI
+1GSqyi1bFBgsRjM0THllIdMbKmJtWwnKW8J+5OgNN8y6Xxv8JmM/Y5vQt2lis0f
qXmG8UTz0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY7JRVcbB4khUN3Gp0
yg+801SXzoFTTa+UGIRLE66jH51aa5VXu99hnv1OiH8tQrjdi8mH6uG/icq4XuIe
NWMF32wHqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSEonWW4HtLbtmS8He1
JNPc/n3dVUm+fM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTAgMBAAGjggG6MIIBtjAM
BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTWRAAyfKgN
/6xPa2buta6bLMU4VDAdBgNVHQ4EFgQUiRlZXg7xafXLvUfhNPzimMxpMJEwFAYD
VR0gBA0wCzAJBgdngQwBBQQBMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwu
Y2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYV9jcmwuY3JsMEsGCCsGAQUFBwEBBD8w
PTA7BggrBgEFBQcwAoYvaHR0cDovL3JlcG9zaXRvcnkuY2EuZXhhbXBsZS5jb20v
aXNzdWluZ19jYS5kZXIwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCsGAQUFBwMCMIGU
BgNVHREEgYwwgYmBGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb22gKQYKKwYBBAGC
NxQCA6AbDBloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29toCYGCCsGAQUFBwgJoBoM
GOWxseeUsOiKseWtkEBleGFtcGxlLmNvbaQZMBcxFTATBgNVBAMMDOWxseeUsOiK
seWtkDANBgkqhkiG9w0BAQsFAAOCAgEAB3UHyqEUNiG3h2cDl9O0jfsIUwOSxSOo
TI9X81QsoCb1JZpcDNJWyvBDalUSChHLAxBxImGa+WZw7dCFxhKLds8NKGtScefk
7FNVxHT7iR77DcaqqyCz3UGYT5nwoPFMJ1Iu3Vb7h1zn9zHn9BlVCFEHr19ORXHp
vjyi4cEU5/1zhfbm09tJE+2F4mrDK10AGG6BD6QTw0vV+vA+pSfxzcEmmfH0lcPL
ORgN4/A/bP4c57A7ZXG1YAbmEDJK07b6wF53EoUumalV7WvynrD9Jx1QrUera3yQ
LhOqfyWz7Ib2+dQnLlaLPw7n7gnSlo8EqfiyuY2XmOlr6i/KBGdWLnxE+t1yC/YC
FKVVykJEItSqyngEKAHZyu6Qh+v68uorMO7nMhWQ/toLEeYxjig38qMi+oJ5oMey
SlNKUQpLRTr7IRdvQ9gM2hHKTv/KrbmCa8vJv+pH0jbvE2WuHRkIQxmK/qYqkXKH
cCHQU8NkafPEeQaE2hidSZV7AUzD4t2VoySASeh5qRC3QhNTIueFEjgBkJVGbynR
nYIS9bOMsNASk8p5PYFcmDhHxOBHInjT5k+ai82xWruI5FV8ITf+qOiVgavPssSa
YFtmhJZx0eimy04HG4O2CobSjQrt7Ue+Yzzi/DWxhPfKPHOKTSqcxvS4ym37F2ly
bO2MTo+BW7w=
-----END CERTIFICATE-----' | docker run --rm -i ghcr.io/digicert/pkilint lint_cabf_smime_cert lint -d -
SubjectKeyIdentifierValidator @ certificate.tbsCertificate.extensions.3.extnValue.subjectKeyIdentifier
    pkix.subject_key_identifier_method_1_identified (INFO)
    
$
```

#### Starting a REST API server with 8 worker processes, listening for requests on TCP/IP port 8000 on all interfaces

```shell
$ docker run --rm -d -p 8000:8000 ghcr.io/digicert/pkilint gunicorn -w 8 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 pkilint.rest:app
7a87146998609343490808cb6a37a8d72c3d5a2bf796af837f37e71e2bc9b144
$ curl -X POST -H "Content-Type: application/json" -d '{"b64":"MIIF1DCCA7ygAwIBAgIUI+v/jTtadau/a5lLVGP50z0FoW8wDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0yMzA3MTgyMzU5NTlaMEIxFjAUBgNVBAMMDVlBTUFEQSBIYW5ha28xKDAmBgkqhkiG9w0BCQEWGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw+egZQ6eumJKq3hfKfED4dE/tL4FI5sjqont9ABVI+1GSqyi1bFBgsRjM0THllIdMbKmJtWwnKW8J+5OgNN8y6Xxv8JmM/Y5vQt2lis0fqXmG8UTz0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY7JRVcbB4khUN3Gp0yg+801SXzoFTTa+UGIRLE66jH51aa5VXu99hnv1OiH8tQrjdi8mH6uG/icq4XuIeNWMF32wHqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSEonWW4HtLbtmS8He1JNPc/n3dVUm+fM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTAgMBAAGjggG6MIIBtjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTWRAAyfKgN/6xPa2buta6bLMU4VDAdBgNVHQ4EFgQUiRlZXg7xafXLvUfhNPzimMxpMJEwFAYDVR0gBA0wCzAJBgdngQwBBQQBMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYV9jcmwuY3JsMEsGCCsGAQUFBwEBBD8wPTA7BggrBgEFBQcwAoYvaHR0cDovL3JlcG9zaXRvcnkuY2EuZXhhbXBsZS5jb20vaXNzdWluZ19jYS5kZXIwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCsGAQUFBwMCMIGUBgNVHREEgYwwgYmBGWhhbmFrby55YW1hZGFAZXhhbXBsZS5jb22gKQYKKwYBBAGCNxQCA6AbDBloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29toCYGCCsGAQUFBwgJoBoMGOWxseeUsOiKseWtkEBleGFtcGxlLmNvbaQZMBcxFTATBgNVBAMMDOWxseeUsOiKseWtkDANBgkqhkiG9w0BAQsFAAOCAgEAB3UHyqEUNiG3h2cDl9O0jfsIUwOSxSOoTI9X81QsoCb1JZpcDNJWyvBDalUSChHLAxBxImGa+WZw7dCFxhKLds8NKGtScefk7FNVxHT7iR77DcaqqyCz3UGYT5nwoPFMJ1Iu3Vb7h1zn9zHn9BlVCFEHr19ORXHpvjyi4cEU5/1zhfbm09tJE+2F4mrDK10AGG6BD6QTw0vV+vA+pSfxzcEmmfH0lcPLORgN4/A/bP4c57A7ZXG1YAbmEDJK07b6wF53EoUumalV7WvynrD9Jx1QrUera3yQLhOqfyWz7Ib2+dQnLlaLPw7n7gnSlo8EqfiyuY2XmOlr6i/KBGdWLnxE+t1yC/YCFKVVykJEItSqyngEKAHZyu6Qh+v68uorMO7nMhWQ/toLEeYxjig38qMi+oJ5oMeySlNKUQpLRTr7IRdvQ9gM2hHKTv/KrbmCa8vJv+pH0jbvE2WuHRkIQxmK/qYqkXKHcCHQU8NkafPEeQaE2hidSZV7AUzD4t2VoySASeh5qRC3QhNTIueFEjgBkJVGbynRnYIS9bOMsNASk8p5PYFcmDhHxOBHInjT5k+ai82xWruI5FV8ITf+qOiVgavPssSaYFtmhJZx0eimy04HG4O2CobSjQrt7Ue+Yzzi/DWxhPfKPHOKTSqcxvS4ym37F2lybO2MTo+BW7w="}' http://localhost:8000/certificate/cabf-smime
{"results":[{"validator":"SubjectKeyIdentifierValidator","node_path":"certificate.tbsCertificate.extensions.3.extnValue.subjectKeyIdentifier","finding_descriptions":[{"severity":"INFO","code":"pkix.subject_key_identifier_method_1_identified","message":null}]}],"linter":{"name":"INDIVIDUAL-LEGACY"}}

$
```

#### Sigstore signature verification

Docker images are signed using [Sigstore](https://www.sigstore.dev/)'s [cosign](https://docs.sigstore.dev/signing/quickstart/) tool.
To verify the signature on a Docker image, [install the cosign utility](https://docs.sigstore.dev/system_config/installation/) and execute the following
command:

```shell
cosign verify --key https://raw.githubusercontent.com/digicert/pkilint/main/docker/cosign_public_key.pem ghcr.io/digicert/pkilint
```

## Usage

Several command line linters are bundled with pkilint, each of which will return the number of reported findings as the
process exit code.

The list of command line linters bundled with pkilint:

* [lint_pkix_cert](#lintpkixcert)
* [lint_cabf_smime_cert](#lintcabfsmimecert)
* [lint_cabf_serverauth_cert](#lintcabfserverauthcert)
* [lint_etsi_cert](#lintetsicert)
* [lint_crl](#lintcrl)
* [lint_ocsp_response](#lintocspresponse)
* [lint_pkix_signer_signee_cert_chain](#lintpkixsignersigneecertchain)


Each of the linters share common command line parameters:

| Parameter           | Default value | Description                                                                                                                                                                                      |
|---------------------|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-s`/`--severity`   | INFO          | Sets the severity threshold for findings. Findings that are below this threshold are not reported.                                                                                               |
| `-f`/`--format`     | TEXT          | Sets the format in which results will be reported. Current options are TEXT, CSV, or JSON.                                                                                                       |
| `--document-format` | DETECT        | Sets the expected format of documents. If a document is not in the specified format, then an error is reported and the linter exits. Current options are BASE64, DER, PEM, and DETECT (default). |

Additionally, each linter has ability to lint document (certificate, CRL, OCSP response, etc.) files as well as output the set of validations
which are performed by each linter. When the `validations` sub-command is specified, the set of validations that are performed by the linter
is output to standard output in CSV format.

When the `lint` sub-command is specified for each linter, a file which contains the document to lint must be specified. The document
may be either DER- or PEM-encoded.

Each of the command line tools wrap various linter Python APIs available within pkilint.

If you have installed the optional REST API, see the usage instructions [below](#rest-api-usage).

### lint_pkix_cert

This is the "base" X.509 certificate linter that lints specified certificates against RFC 5280 and related RFCs.

### lint_cabf_smime_cert

This tool lints end-entity S/MIME certificates against the
[CA/Browser Forum S/MIME Baseline Requirements](https://cabforum.org/smime-br/). 

The `lint` sub-command requires that the user provide the certificate type/profile of the certificate so that the appropriate
validations are performed. There are three options:

1. Explicitly specify the type of S/MIME certificate using the `-t`/`--type` option. This may be useful when linting S/MIME certificates where the policy OIDs in the certificate do not map to an S/MIME validation level and generation.
2. Have the linter detect the type of certificate using the `-d`/`--detect` option. In this case, the linter will determine the validation level and generation using the policy OIDs included in the certificate. If a reserved CA/Browser Forum policy OID is found, then the corresponding validation level and generation are used. If no such reserved OIDs are found, then the optional mapping file (see below) is used. If no OIDs in the mapping file are found, then the tool exits with an error.
3. Have the linter detect the type of certificate using the `-g`/`--guess` option. This option uses the same identification procedure as the `--detect` option, with one major difference. Instead of exiting with an error upon being unable to find an appropriate policy OID, this option instead directs the linter to use heuristics to determine the validation level and generation.

Options 2 and 3 allow for the use of an optional mapping file, specified using the `-m`/`--mapping` option. This file contains one or more mappings from policy OIDs to the corresponding validation level and generation.

For example, the following mapping file is used to map policy OID `1.2.3.4.5.6` to the `MAILBOX-LEGACY` validation level and generation and `1.2.3.4.5.7` to the `SPONSORED-LEGACY` validation level and generation:

~~~
1.2.3.4.5.6=MAILBOX-LEGACY
1.2.3.4.5.7=SPONSORED-LEGACY
~~~

The `-o`/`--output` option is used to specify that the validation level and generation used by the linter is written to standard error. This is useful when using the `--guess` option to see which validation level and generation was determined by the heuristics logic.

The `--validity-period-start` option is used to override how the issuance date/time of a certificate is determined. Many requirements are applicable based on the date/time of issuance of certificates, so this option is useful
to evaluate whether a certificate complies with an upcoming requirement. There are three possible types of values for this option:

1. `DOCUMENT`: Use the value of the `notBefore` field to determine the issuance date/time. This is the default value.
2. `NOW`: Use the current date/time to override the issuance date/time.
3. An ISO 8601 timestamp: Use the specified timestamp to override the issuance date/time.

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

### lint_cabf_serverauth_cert

This tool lints TLS server authentication certificates (both final and pre-certificates), Intermediate CA certificates, Root CA certificates,
and OCSP delegated responder certificates against the
[CA/Browser Forum TLS Baseline Requirements](https://cabforum.org/baseline-requirements-documents/), notably with
support for linting against the profile for certificates specified in ballot [SC-62](https://cabforum.org/2023/03/17/ballot-sc62v2-certificate-profiles-update/).

The `lint` sub-command requires that the user provide the certificate type/profile of the certificate so that the appropriate
validations are performed. There are two options:

1. Explicitly specify the type of certificate using the `-t`/`--type` option.
2. Have the linter detect the type of certificate using the `-d`/`--detect` option. In this case, the linter will determine the certificate type using the values of various extensions and fields included in the certificate. The detection procedure may not always be accurate, so it is recommended to use the `--type` option for the best results.

Several parts of the TLS Baseline Requirements supersede requirements specified in RFC 5280. For example, RFC 5280 specifies that the `nameConstraints` extension MUST be critical, but the TLS Baseline Requirements allows this extension to be non-critical. By default, findings related to the PKIX standards that are superseded by the
TLS Baseline Requirements are not reported. To report superseded findings, specify the `--report-all` option.

The `-o`/`--output` option is used to specify that the certificate type used by the linter is written to standard error. This is useful when using the `--detect` option to see which certificate type was determined by the heuristics logic.

The `--validity-period-start` option is used to override how the issuance date/time of a certificate is determined. Many requirements are applicable based on the date/time of issuance of certificates, so this option is useful
to evaluate whether a certificate complies with an upcoming requirement. There are three possible types of values for this option:

1. `DOCUMENT`: Use the value of the `notBefore` field to determine the issuance date/time. This is the default value.
2. `NOW`: Use the current date/time to override the issuance date/time.
3. An ISO 8601 timestamp: Use the specified timestamp to override the issuance date/time.

#### Example command execution

```shell
$ echo '-----BEGIN CERTIFICATE-----
MIIFhzCCBG+gAwIBAgIKd3d3d3d3d3d3dzANBgkqhkiG9w0BAQsFADBFMQswCQYD
VQQGEwJVUzETMBEGA1UEChMKQ2VydHMgUiBVczEhMB8GA1UEAxMYQ2VydHMgUiBV
cyBJc3N1aW5nIENBIEcxMB4XDTIzMDYwMjAwMDAwMFoXDTI0MDYwMTIzNTk1OVow
ADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJjfM1nBO6c4jF2eL+PP
y+pQOjb+d6eYUk3CypR4j+bzV104d/LT12ukkEL3cR5YapINlZFfMnGxkxz12+AK
1tKo2m8agDlXTeWvl1hS0axCGOGZL16wvR078oxejK2nmfWlUdFhSmWpFyOeuxCG
tTaeqjOHjABvKOwqXNlRTlw0CCQ6j2GFqLGPbJ5yfqGLiDGBB+iVdS8oCQ6RtPks
HH/FNBVeWbwhHE6jrH+yTHbkxJzZwc5W86YHH0PwmsXdCT9gdyfYD1UFm4Ly9iBA
CgUEYbnXEeYmiZV40yDFbwkZ2JvhmtjN4zJpEc4/DP40wMolSZ1F0Gd+2XjJDjSV
iDkCAwEAAaOCArwwggK4MB8GA1UdIwQYMBaAFGpOUL+YaJ1beyB11FkBeUhmkjIG
MB0GA1UdEQEB/wQTMBGCD3d3dy5leGFtcGxlLmNvbTAOBgNVHQ8BAf8EBAMCB4Aw
HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDYGA1UdHwQvMC0wK6ApoCeG
JWh0dHA6Ly9jcmwuY2VydHNydXMuY29tL0lzc3VpbmdDQS5jcmwwEwYDVR0gBAww
CjAIBgZngQwBAgEwawYIKwYBBQUHAQEEXzBdMCQGCCsGAQUFBzABhhhodHRwOi8v
b2NzcC5jZXJ0c3J1cy5jb20wNQYIKwYBBQUHMAKGKWh0dHA6Ly9jYWNlcnRzLmNl
cnRzcnVzLmNvbS9Jc3N1aW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAwggF9BgorBgEE
AdZ5AgQCBIIBbQSCAWkBZwB3AHb/iD8KtvuVUcJhzPWHujS0pM27KdxoQgqf5mdM
Wjp0AAABiPi9rwAAAAQDAEgwRgIhAInr/dvQgE8xMHPYGfO0O0SWM6mVMosn7lou
lKdMyLyeAiEAoDkG4x8Vb/ON0LbScu6OabUj/yuKQgOhJ3QzeMSsrxgAdQBIsONr
2qZHNA/lagL6nTDrHFIBy1bdLIHZu7+rOdiEcwAAAYj4va8yAAAEAwBGMEQCIHmr
Nj/5IrHhLfRXFledOIVw5wuKBMvMNzuRXheNBo83AiA+uJDHaE5gTN4E+nLf0bSV
kz4UCyEyrTkUP1VGXrKDFgB1ADtTd3U+LbmAToswWwb+QDtn2E/D9Me9AA0tcm/h
+tQXAAABiPi9rywAAAQDAEYwRAIgOvSSVYIOHQamIZDDn/VBPidP0elZbtVQvpse
DBVIgAUCIFRidEFgm6Xl7HnxMkai8KOLa055sKZ8bNvVyzoUgwcnMA0GCSqGSIb3
DQEBCwUAA4IBAQBd9/ZFYiJ+k9yeWmIrPIrxBpuyGHfO+Tbc6jH4trtt53v+UhAg
/9YSv+zkfXPF7izcJTjfnwMsGZf3cH2gyn5p+sc8mX9mQQC9WEQ60z457Cg6WNqi
LxSZYLrSKZ4ZVPg0hkXsjeaKCZ3z7yu5ozAOBp9Fk3CZtkP1LlbS/heHGcywnTZn
pHbT2YPixrn8+qi+5aAZyPrhiNKynKI1C6hhCb/8TmXu7h2f31l0ZhDZ+AGZN8/q
yYM8aZGzLp3gLspWvfO2/Cee63bdQmWL6CUOUpaGxF8eAxstXZCHr95HR6i9+Txu
3XxCq8enw/MZWJ1jmEp6jXrehGQQhXvmTU6f
-----END CERTIFICATE-----' > dv_final_clean.pem

$ lint_cabf_serverauth_cert lint -d dv_final_clean.pem

$
```

### lint_etsi_cert

For further information on this linter, see [the Wiki page](https://github.com/digicert/pkilint/wiki/lint_etsi_cert).

This tool lints certificates against the profiles specified in ETSI EN 319 412 and TS 119 495. Currently, the tool
has the most comprehensive support for website authentication certificates, but support for electronic signature,
electronic seal, and timestamping certificates is planned.

The `lint` sub-command requires that the user provide the certificate type/profile of the certificate so that the appropriate
validations are performed. There are two options:

1. Explicitly specify the type of certificate using the `-t`/`--type` option.
2. Have the linter detect the type of certificate using the `-d`/`--detect` option. In this case, the linter will determine the certificate type using the values of various extensions and fields included in the certificate. The detection procedure may not always be accurate, so it is recommended to use the `--type` option for the best results.

Several parts of EN 319 412 and TS 119 495 supersede requirements specified in the TLS Baseline Requirements and RFC 5280. For example, the TLS Baseline Requirements requires that certificate validity periods be 398 days or less. However, this requirement need not be followed for PSD2 website authentication certificates that are not trusted
by browsers. By default, such findings are not reported. To report superseded findings, specify the `--report-all` option.

The `-o`/`--output` option is used to specify that the certificate type used by the linter is written to standard error. This is useful when using the `--detect` option to see which certificate type was determined by the heuristics logic.

#### Example command execution

```shell
$ echo '-----BEGIN CERTIFICATE-----
MIIHMTCCBRmgAwIBAgIQVZHNRxiZp9LoR1nlajD1DDANBgkqhkiG9w0BAQsFADCB
oTELMAkGA1UEBhMCR1IxNjA0BgNVBAoTLUhFTExFTklDIEVYQ0hBTkdFUyAtIEFU
SEVOUyBTVE9DSyBFWENIQU5HRSBTQTEvMC0GA1UEAxMmQVRIRVggUXVhbGlmaWVk
IFdFQiBDZXJ0aWZpY2F0ZXMgQ0EtRzMxDzANBgNVBAcTBkF0aGVuczEYMBYGA1UE
YRMPVkFURUwtMDk5NzU1MTA4MB4XDTI0MDQxMTE0MTY1NVoXDTI1MDQxMTE0MTY1
NVowgcMxCzAJBgNVBAYTAkdSMTYwNAYDVQQKEy1IRUxMRU5JQyBFWENIQU5HRVMg
LSBBVEhFTlMgU1RPQ0sgRVhDSEFOR0UgU0ExGDAWBgNVBGETD1ZBVEVMLTA5OTc1
NTEwODEdMBsGA1UEAxMUd2ViZHNzLmF0aGV4Z3JvdXAuZ3IxDzANBgNVBAcTBkF0
aGVuczETMBEGCysGAQQBgjc8AgEDEwJHUjEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdh
bml6YXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4IRER3+RS
dMkB84htWhzmrcFTqJ47yJtZAgvDxw0aWYWVtyW2SMtygVUZSfp5ewE8OA9tdCa6
oIuap6hKgZpQnkxS9RP0JRyHrJjxOc4sUUtbOHMCV5hq4Lkonh01DAsad9tVqR4n
aUSHsPI8v+93fjigi3vBsf5nGeBRrCTBYs8IKqoCC+Z2WWbwRCB6ct+ODsqbLwRx
T54WY9iTaCNc/71rUlvIo3nkd/H17MCkoBdv4Ec3NG1Jo18FnkATyM12Xzhet+Wv
vx0yjewRrFxak/wGZ4GGX1Dzy4wHfsceQjAtiZk2oWcn3/mk6oVA0ynF2a/4CmT1
OZiWGOTqNnxTAgMBAAGjggI/MIICOzAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwHwYDVR0jBBgwFoAUIpkkVwZsVnWO2+t9eWWcUzWp0ZEwLQYIKwYBBQUH
AQMEITAfMAgGBgQAjkYBATATBgYEAI5GAQYwCQYHBACORgEGAzCBlwYIKwYBBQUH
AQEEgYowgYcwOAYIKwYBBQUHMAGGLGh0dHA6Ly9vY3NwLmF0aGV4Z3JvdXAuZ3Iv
QXRoZXhRdWFsaWZpZWRDQUczMEsGCCsGAQUFBzAChj9odHRwOi8vcmVwby5hdGhl
eGdyb3VwLmdyL0FUSEVYUXVhbGlmaWVkV0VCQ2VydGlmaWNhdGVzQ0FHMy5jcnQw
JQYDVR0gBB4wHDAPBg0rBgEEAYHlWgEDZAEEMAkGBwQAi+xAAQYwTwYDVR0fBEgw
RjBEoEKgQIY+aHR0cDovL2NybC5hdGhleGdyb3VwLmdyL0FUSEVYUXVhbGlmaWVk
V0VCQ2VydGlmaWNhdGVzQ0FHMy5jcmwwHQYDVR0OBBYEFNO1Ri+h7gAw1BnwJi1m
HFV+L6htMA4GA1UdDwEB/wQEAwIHgDB7BgNVHREEdDByghR3ZWJkc3MuYXRoZXhn
cm91cC5ncoIYd2ViZHNzbW9jay5hdGhleGdyb3VwLmdyghp3ZWJkc3MtcnB4cjEu
aW5ldC5oZWxleC5ncoIPZHNzLmF0aGV4bmV0LmdyghNkc3Ntb2NrLmF0aGV4bmV0
LmdyMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJl4huEpr01gxqGh
FzkCbhZYW48Bv+zGQodfBnhISH5Dj9Apb2pUCJiPIGy6NQ3nHygyy1y2aW+1ExrZ
6ZCmtmw2/isk8q9wKa4PS/ip1+IzOin67XmYAz+t03MRl569wtzH+WPL2hb5Zmsw
AkTP6/N9Jp1I9cryvHO2ZCEYZreWtgvJQaDBQ/qteUKnVNLyuJle9hAYvsWEbgIO
xlWaDzPnWYYjZuXbyowImmjhufFyrJ2ngwwgw1sI0Se5vGOWWj+i/KBqLbwpp11I
yXAJkhNTJVxI5B7BpAqoMGOlqf4w4eCqU/HUKL9ZIOHSClPTzaXS45ppPyb+zzLB
u4vt0PJTAh3wnujcRZ3NxmetsehqunSpyKg0MzL2FDpxD31XHzmlpq5hQGgX1QF3
0Wl3IADw5JzT4ApHW4ucsLr22HJBTnFab/tbviqg2HcVDAksUqZbPqNCenN/BW3J
rhXwewWAfHE4LnDQBlAbq95LuijvHx3MaTt8y7wPSOizYTpry19uHT0aaxXfLivh
YnIjcWwNwowxjVLSVBK0TBvEUVF2DwDNLRfX2aSpt0rq3rxtNcjvJvwHJrDLio8y
fSyJXu4qGbQ3OwuuJXaEPiBANUEckaPKg5pdua4Lwt708kOG54E7pzz3xLEjtODU
+9Ru72tw8lf1RlWwp5ZI+7CByD0W
-----END CERTIFICATE-----' > qncp_w_gen.pem

$ lint_etsi_cert lint -d qncp_w_gen.pem
SubjectKeyIdentifierValidator @ certificate.tbsCertificate.extensions.6.extnValue.subjectKeyIdentifier
    pkix.subject_key_identifier_method_1_identified (INFO)

$
```

### lint_crl

This tool lints CRLs against the RFC 5280 as well as against the CA/Browser Forum profile for CRLs. It is anticipated that this
linter will be expanded to encompass the profile for CRLs specified in ballot [SC-63](https://cabforum.org/2023/07/14/ballot-sc-063-v4make-ocsp-optional-require-crls-and-incentivize-automation/).

### lint_ocsp_response

This tool lints OCSP responses against the RFC 6960 profile.

### lint_pkix_signer_signee_cert_chain

This tool lints subject/issuer certificate pairs to ensure consistency of fields and extension values across certificates.

### REST API Usage

The REST API is implemented as an ASGI application using the [FastAPI](https://fastapi.tiangolo.com) framework. Notably, FastAPI
does not come bundled with a server component, so one will need to be installed separately. If you ran the `pipx` commands
in the [REST API Installation](#rest-api-installation) section above, then [Uvicorn](https://www.uvicorn.org/) has been installed. Otherwise, you can
make your choice of server by reviewing the documentation for [deploying FastAPI](https://fastapi.tiangolo.com/deployment/manually/).

Assuming that Uvicorn has been installed via pipx, the REST API server can be started with the following command:

```shell
uvicorn pkilint.rest:app
```

This command will start the REST API server and listen for incoming requests on TCP/IP port 8000 of the loopback interface.
Once the REST API server has been started, documentation will be available on the following endpoints:

* [Swagger UI](http://127.0.0.1:8000/docs)
* [ReDoc](http://127.0.0.1:8000/redoc)
* [OpenAPI Schema](http://127.0.0.1:8000/openapi.json)

## Bugs?

If you find a bug or other issue with pkilint, please create a GitHub issue.

## Contributing

As we intend for this project to be an ecosystem resource, we welcome contributions. It is preferred that proposals for new
features be filed as GitHub issues so that design decisions, etc. can be discussed prior to submitting a pull request.

This project uses [Black](https://github.com/psf/black) code formatter. The CI/CD pipeline checks for compliance with
this format, so please ensure that any code contributions follow this format.

## Acknowledgements

pkilint is built on several open source packages. In particular, these packages are dependencies of this project:

| Name               | License                              | Author                                                         | URL                                               |
|--------------------|--------------------------------------|----------------------------------------------------------------|---------------------------------------------------|
| cryptography       | Apache Software License; BSD License | The Python Cryptographic Authority and individual contributors | https://github.com/pyca/cryptography              |
| fastapi            | MIT License                          | Sebastián Ramírez                                              | https://github.com/tiangolo/fastapi               |
| iso3166            | MIT License                          | Mike Spindel                                                   | http://github.com/deactivated/python-iso3166      |
| iso4217            | Public Domain                        | Hong Minhee                                                    | https://github.com/dahlia/iso4217                 |
| publicsuffixlist   | Mozilla Public License 2.0 (MPL 2.0) | ko-zu                                                          | https://github.com/ko-zu/psl                      |
| pyasn1             | BSD License                          | Christian Heimes and Simon Pichugin                            | https://github.com/pyasn1/pyasn1                  |
| pyasn1-alt-modules | BSD License                          | Russ Housley                                                   | https://github.com/russhousley/pyasn1-alt-modules |
| pyasn1-fasder      | MIT License                          | Corey Bonnell                                                  | https://github.com/cbonnell/pyasn1-fasder         |
| python-dateutil    | Apache Software License; BSD License | Gustavo Niemeyer                                               | https://github.com/dateutil/dateutil              |
| python-iso639      | Apache Software License              | Jackson L. Lee                                                 | https://github.com/jacksonllee/iso639             |
| validators         | MIT License                          | Konsta Vesterinen                                              | https://github.com/kvesteri/validators            |

The pkilint maintainers are grateful to the authors of these open source contributions.
