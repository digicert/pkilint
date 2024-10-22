from pkilint import pkix, loader
from pkilint.pkix import crl, name, extension
from pkilint.pkix.crl import crl_validator


def _create_crl_validator():
    return crl.create_pkix_crl_validator_container(
        [
            pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
            pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS),
        ],
        [
            crl.create_issuer_validator_container([]),
            crl.create_validity_validator_container(),
            crl.create_extensions_validator_container([]),
        ],
    )


def test_revoked_certificates_empty():
    pem = """-----BEGIN X509 CRL-----
MIIBYDBKAgEBMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAoTC0NlcnRzICdyIFVz
Fw0yNDA0MTUxNDMzMDBaFw0yNDA1MTUxNDMzMDBaMAAwDQYJKoZIhvcNAQELBQAD
ggEBAGhq9yTTM2ZjzAxyNvXpVbOI4xQhC0L6pdjsZ13d3QFi41QvRFib13fHgcBm
+hWXFSmOT8qgMlIk74y01DBCmrVyn6mTznr49Vy9k6eBEs34F9EtQrJ5MlYNghX2
8UNNTMbQS/T7aYQuVWp4VRZsM2ZFRC1XxDdj85qraRhhc6fDGS3PS6m5vnRuZlVv
3wVB2N2zutQeZcxHDbAa68rSS3fK8jdKjC8uzbYhCvWYIc/ZUB0c+o9clwbZdkl4
eC6gxZ1/uD98+GilFUdX9JNVsi6Il1x9Upm+Oz6JZ43Ly2+yuQZu2rohZNxEzv/f
rzDRkyHn2a+5mqqc2J9asb6RFUs=
-----END X509 CRL-----"""

    doc_validator = _create_crl_validator()

    crl = loader.load_pem_crl(pem, None, None, None)

    results = doc_validator.validate(crl.root)

    assert any(
        r
        for r in results
        if any(r.finding_descriptions)
        and (
            r.finding_descriptions[0].finding
            == crl_validator.RevokedCertificatesEmptyValidator.VALIDATION_REVOKED_CERTIFICATES_EMPTY
        )
    )


def test_clean_no_revoked_certificates():
    pem = """-----BEGIN X509 CRL-----
MIIBzTCBtgIBATANBgkqhkiG9w0BAQsFADAiMQswCQYDVQQGEwJYWDETMBEGA1UE
CgwKQ1JMcyAnciBVcxcNMjQwMzI1MTg0NzAwWhcNMjQwNDAxMTg0NzAwWqBgMF4w
CgYDVR0UBAMCAQEwHwYDVR0jBBgwFoAU/NE0t8uklbG2WeoLBWIe6JqPtDowLwYD
VR0cAQH/BCUwI6AeoByGGmh0dHA6Ly9mb28uZXhhbXBsZS9jcmwuZGxshAH/MA0G
CSqGSIb3DQEBCwUAA4IBAQAN8oDSvWsg3JvUJ4MkXvczaFb72VH0J/VL5PV2cBSm
MfaVBKnUsNr1IcxT06KF8gNrDTpKqJ9fetO290swZfcPt9sEVUBVQUpdlQc3tya1
jYWmFkA3tkpqH5rBCQa3CBm1Cg8cbFBtwWgWr70NsVvfD6etjAEP9Ze+MSXnGV0p
w9EeOV07HnSD/PGQwqCiaSn5DdIDVoH8eFSGmgNLw+b4SwUjmz8PqsZwvHxJvleV
1D8cj7zdR4ywgRMjEfJZ8Bp+Tdu64Gv0doDS0iEJIshLHYkcW1okpq/tPm8kKAbD
reparePNQwhScVcDiSL73eEBIPokgG3QhohiucP5MeF1
-----END X509 CRL-----"""

    doc_validator = _create_crl_validator()

    crl = loader.load_pem_crl(pem, None, None, None)

    results = doc_validator.validate(crl.root)

    assert not any(r for r in results if any(r.finding_descriptions))
