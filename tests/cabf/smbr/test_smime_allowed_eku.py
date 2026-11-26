import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from pkilint import document, loader
from pkilint.cabf import smime
from pkilint.cabf.smime import smime_constants, smime_extension
from pkilint.pkix import certificate

_VALIDATOR_CLASS = smime_extension.AllowedExtendedKeyUsageValidator
_PROHIBITED_EKU_PRESENT = _VALIDATOR_CLASS.VALIDATION_PROHIBITED_EKU_PRESENT.code
_DOC_SIGNING_OID = ObjectIdentifier("1.3.6.1.4.1.311.10.3.12")

_KEY = ec.generate_private_key(ec.SECP256R1())

_MULTIPURPOSE_SERVER_AUTH_BEFORE_SUNSET_PEM = """-----BEGIN CERTIFICATE-----
MIIFljCCA/6gAwIBAgIRAMa90ZOdwBPyulBDZYxupdcwDQYJKoZIhvcNAQELBQAw
QjERMA8GA1UEAxMIU21pbWUgQ0ExCzAJBgNVBAsTAkNBMRMwEQYDVQQKEwpFeGFt
cGxlIENvMQswCQYDVQQGEwJVUzAeFw0yNjExMjUwNjE0MzRaFw0yNzExMjUwNjE0
MzRaMGYxHjAcBgNVBAMMFXRlc3RlbWFpbEB0ZXN0aW5nLmNvbTEXMBUGA1UEBxMO
U2FsdCBMYWtlIENpdHkxCzAJBgNVBAYTAlVUMQ0wCwYDVQQqEwRSZWFsMQ8wDQYD
VQQEEwZQZXJzb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC3BHMC
ewJwI3BBlFsr60OUqfDDl0eW8d+Sz1P/G0drUOGGBwp2abOP+JHRnNcr8Xg8mWSO
vKaRmXh4BjD4CTgHPCz3JKmb/GDvb14wBLHRDbHwnut8pTb+JE5r8HPikxt3R8tn
XL19+lP5L3y3vCj9sYxeQ/LMGw7amHDzso4pM3vtAN7valW0Za6AJnIhz/IlsNcJ
J4zrrmlBPUkpdyFcXYhOhOzmavCqP5wv9zTUL/t5SMBDKL0LydIPAGgaSa/HG8EI
kQhSwYOfcPSTeZH+R5o89nqXRazFYW1ODmU4kf2VJh+9NeI646MwbQx3dpWgfMW2
WRp5AKAJNGQDKHAJL+ZGtCS5knpM4Y0RVYu/lkPdHrHWP11PkpQ4EoFZSeQNDoz8
fj4LdPno9GDeiwEyOEtdpEKOI2Z3+21O09J2WolIGbTxmK/iBA89xwhGlwZ+arE7
m4DW1rVBXZEHQAjwGKJSIGvkGBTkYMylWi7o3w74z6i+eMYq9c4BJjB0r3ECAwEA
AaOCAWEwggFdMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDBAYI
KwYBBQUHAwEwHQYDVR0OBBYEFI+V4t6rYNwzRdwmFhCmyyxrmzeRMB8GA1UdIwQY
MBaAFHy1w2n8B+1Di8gPDVpVZPAWsZc+MFsGCCsGAQUFBwEBBE8wTTAjBggrBgEF
BQcwAYYXaHR0cDovL29jc3AuZXhhbXBsZS5jb20wJgYIKwYBBQUHMAKGGmh0dHA6
Ly9leGFtcGxlLmNvbS9jYTEuY3J0MCAGA1UdEQQZMBeBFXRlc3RlbWFpbEB0ZXN0
aW5nLmNvbTAUBgNVHSAEDTALMAkGB2eBDAEFAQIwVwYDVR0fBFAwTjAloCOgIYYf
aHR0cDovL2NybDEuZXhhbXBsZS5jb20vY2ExLmNybDAloCOgIYYfaHR0cDovL2Ny
bDIuZXhhbXBsZS5jb20vY2ExLmNybDANBgkqhkiG9w0BAQsFAAOCAYEAMExBCerX
1tmQleDdWqsJytdiDsPQCYkGmkxYH83DpnMZavH14dQzcEAOTGKGoxUI+Uk8Yxb2
g9PRYk89c8l6TaAk1E2Thk2wcALSxbQHLn+apnudGurIRXpEARfRYIKvFnk38aGt
TTcp2y2juSt0YJcYeKH3mYnEs+88bntl8wcFxq+YTTBVpJgMMJg0qd6jzpGagJP6
UyIkq8QgA+lMjwOm338wuqlbZR9HOHLlj2v346uuW0sypjneTvVB8rK/ewnyF0no
k0cgkmveQ+6wutb3dZ8Fcn7Ku+h0WkU7pVJGmPP0zwE1q086olE2cRgj6ar2NEeB
cYLibXMPJ5wuRmH38I2CEKCn5zPrsvQBao0QoAZYWD7CS1S/HpbSdHu4RwTbwi8D
buq0CBWqWkaVb3kUSOWbEBhjC34KR3gOs26BtXt6f+5xsbMQznIJSsHfw0nvUTov
+NBREL4zVMKzUVkBAoZ9zC1H5KqzWJcS2F9IglMCwry+A67aKgYfnhhU
-----END CERTIFICATE-----"""

_STRICT_CLIENT_AUTH_AFTER_SUNSET_PEM = """-----BEGIN CERTIFICATE-----
MIIF0DCCBDigAwIBAgIQUZWhMM6THe97MZM00tPhWjANBgkqhkiG9w0BAQsFADBC
MREwDwYDVQQDEwhTbWltZSBDQTELMAkGA1UECxMCQ0ExEzARBgNVBAoTCkV4YW1w
bGUgQ28xCzAJBgNVBAYTAlVTMB4XDTI3MTEyNTA0MjEwMVoXDTI4MDEyNTA0MjEw
MVowgaAxHjAcBgNVBAMMFXRlc3RlbWFpbEB0ZXN0aW5nLmNvbTETMBEGA1UEChMK
RXhhbXBsZSBDbzEXMBUGA1UEBxMOR3VhdGVtYWxhIENpdHkxCzAJBgNVBAYTAkdU
MSMwIQYDVQRhExpMRUlYRy01Mjk5MDBUOEJNNDlBVVJTRE81NTENMAsGA1UEKhME
UmVhbDEPMA0GA1UEBBMGUGVyc29uMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB
igKCAYEAtY9R2ptwQ0N0RXjsoMJaatwrpBbLWKFE8L2YEIfYo3dHSc/3c/XQCgrE
q2oJz+fsAah/jX+PR/oOsI4I7eg33e+4UI3ReOX4XurNTiLaUPAgdQeeC0YT4zGu
7CHo+32evf1oSW9aVGvwhFHxbijaZMzzdJauNJHuYSDYT4jebN7pdynfXXxGDGCA
4E3v1oPfHwoFHrVVFyR17GfGfDqgHTjBE7pcsKAxUS+L6erH38CSUk7F4IRU2mfG
QmXmSXhHx9mvqDSTurOCyC9ZzGL685dxpc7NZZ1cYbn1lAAEh8tZ5OnOs4xw9ggi
D0BOl3owAHPhHFyFQ/uIhEpYOhtGX6KkebZAqS1yi1eriIH52HJr8i2lQnkLVeC5
DPTm8VY7+LEjaxGmmUt0kTMj3APxOpuzHTkfPzF2D7MeWBMcjsMWYYJBoRuOsv++
rkOEpaXovzFX6pymFEx7/GgpCQeKWgDPYfoBqcUvI+sh92Mbct4u5lPQMbO23ang
ndnGBG0/AgMBAAGjggFhMIIBXTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYI
KwYBBQUHAwQGCCsGAQUFBwMCMB0GA1UdDgQWBBQthdXsMF/0o8iruUj6PYTBlkSa
MzAfBgNVHSMEGDAWgBTZAfHyBGXoh/1SVVM9E81/dpHotjBbBggrBgEFBQcBAQRP
ME0wIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmV4YW1wbGUuY29tMCYGCCsGAQUF
BzAChhpodHRwOi8vZXhhbXBsZS5jb20vY2ExLmNydDAgBgNVHREEGTAXgRV0ZXN0
ZW1haWxAdGVzdGluZy5jb20wFAYDVR0gBA0wCzAJBgdngQwBBQMDMFcGA1UdHwRQ
ME4wJaAjoCGGH2h0dHA6Ly9jcmwxLmV4YW1wbGUuY29tL2NhMS5jcmwwJaAjoCGG
H2h0dHA6Ly9jcmwyLmV4YW1wbGUuY29tL2NhMS5jcmwwDQYJKoZIhvcNAQELBQAD
ggGBADLHD7oN+AszQnRX2O4vVZu6SqKv9StJtSjlczqniNddJ5aZ9KWv5eLgih8+
EVSeu1Rsq7DL/nXkfJ2SmlDtECpfv64rECDMAGyB/AE553+AaA/4eD0kqZ9Cmopw
tGlwou1MEBtIECScKR3qqwa9DtjQpxMZ220rza5j8Yygbm7IfWa83aWjSNP8JlML
sNKNyF5F/zws2m4TSapo57yCiMpDJmos9KAyXJ0LPIEL83lzeGX3eVr4y+VIr0il
jTLkcYeFAD8qsyJz48stH6EDexfZ/kNYd3hp7bB+WCuV4j5ykfxP2UJifoNPKc/A
hY4hTH4dCqfAEVU0W2lEe18Y0BBIp5BdyvD35OlxvuZVOV586WdpeGgOdgWWUbKB
R0/Vd4yaccrBz0ZKz24uu604AY/CA2QfourOn9J9AxMLmqR7/druBXqE73WbrMaQ
hMG+/dPPgj6AbKEjceQ4RBfiqekyTs9mQGEkSGNKzvY02gLRdAgTGFQavHQBZB2G
/x6ABA==
-----END CERTIFICATE-----"""


def _create_certificate(not_before: datetime.datetime, ekus):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=90))
        .add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
        .sign(_KEY, hashes.SHA256())
    )

    return loader.RFC5280CertificateDocumentLoader().load_pem_document(
        cert.public_bytes(serialization.Encoding.PEM).decode()
    )


def _lint_cert_doc(
    cert,
    validation_level,
    generation,
    validity_period_start_retriever=None,
):
    validator = certificate.create_pkix_certificate_validator_container(
        smime.create_decoding_validators(),
        smime.create_subscriber_validators(
            validation_level,
            generation,
            validity_period_start_retriever,
        ),
    )

    results = validator.validate(cert.root)

    return {
        fd.finding.code
        for r in results
        for fd in r.finding_descriptions
        if r.validator.name == _VALIDATOR_CLASS.__name__
    }


def _lint(
    generation: smime_constants.Generation,
    not_before: datetime.datetime,
    ekus,
    validity_period_start_retriever=None,
):
    cert = _create_certificate(not_before, ekus)

    return _lint_cert_doc(
        cert,
        smime_constants.ValidationLevel.MAILBOX,
        generation,
        validity_period_start_retriever,
    )


def _lint_pem(pem: str):
    cert = loader.RFC5280CertificateDocumentLoader().load_pem_document(pem)
    validation_level, generation = smime.determine_validation_level_and_generation(cert)

    return _lint_cert_doc(cert, validation_level, generation)


def test_multipurpose_other_eku_allowed_before_sunset():
    before_sunset = datetime.datetime(
        2027, 6, 30, 23, 59, 59, tzinfo=datetime.timezone.utc
    )

    assert (
        _lint(
            smime_constants.Generation.MULTIPURPOSE,
            before_sunset,
            [ExtendedKeyUsageOID.EMAIL_PROTECTION, _DOC_SIGNING_OID],
        )
        == set()
    )


def test_multipurpose_prohibited_eku_before_sunset_pem():
    assert _lint_pem(_MULTIPURPOSE_SERVER_AUTH_BEFORE_SUNSET_PEM) == {
        _PROHIBITED_EKU_PRESENT
    }


@pytest.mark.parametrize(
    "generation",
    [smime_constants.Generation.MULTIPURPOSE, smime_constants.Generation.LEGACY],
)
@pytest.mark.parametrize(
    "prohibited_eku",
    [
        ExtendedKeyUsageOID.SERVER_AUTH,
        ExtendedKeyUsageOID.CODE_SIGNING,
        ExtendedKeyUsageOID.TIME_STAMPING,
        ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
    ],
)
def test_explicitly_prohibited_ekus_before_sunset(generation, prohibited_eku):
    before_sunset = datetime.datetime(
        2027, 6, 30, 23, 59, 59, tzinfo=datetime.timezone.utc
    )

    assert _lint(
        generation,
        before_sunset,
        [ExtendedKeyUsageOID.EMAIL_PROTECTION, prohibited_eku],
    ) == {_PROHIBITED_EKU_PRESENT}


def test_multipurpose_client_auth_allowed_after_sunset():
    at_sunset = datetime.datetime(2027, 7, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    assert (
        _lint(
            smime_constants.Generation.MULTIPURPOSE,
            at_sunset,
            [
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ],
        )
        == set()
    )


def test_strict_client_auth_prohibited_after_sunset():
    assert _lint_pem(_STRICT_CLIENT_AUTH_AFTER_SUNSET_PEM) == {_PROHIBITED_EKU_PRESENT}


def test_multipurpose_other_eku_prohibited_at_sunset():
    at_sunset = datetime.datetime(2027, 7, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    assert _lint(
        smime_constants.Generation.MULTIPURPOSE,
        at_sunset,
        [ExtendedKeyUsageOID.EMAIL_PROTECTION, _DOC_SIGNING_OID],
    ) == {_PROHIBITED_EKU_PRESENT}


def test_legacy_other_eku_prohibited_at_sunset():
    at_sunset = datetime.datetime(2027, 7, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    assert _lint(
        smime_constants.Generation.LEGACY,
        at_sunset,
        [ExtendedKeyUsageOID.EMAIL_PROTECTION, _DOC_SIGNING_OID],
    ) == {_PROHIBITED_EKU_PRESENT}


def test_multipurpose_other_eku_respects_validity_period_start_override():
    before_sunset = datetime.datetime(
        2027, 6, 30, 23, 59, 59, tzinfo=datetime.timezone.utc
    )
    at_sunset = datetime.datetime(2027, 7, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    assert _lint(
        smime_constants.Generation.MULTIPURPOSE,
        before_sunset,
        [ExtendedKeyUsageOID.EMAIL_PROTECTION, _DOC_SIGNING_OID],
        validity_period_start_retriever=document.StaticValidityPeriodStartRetriever(
            at_sunset
        ),
    ) == {_PROHIBITED_EKU_PRESENT}
