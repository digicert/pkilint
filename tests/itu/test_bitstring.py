from pyasn1.type.univ import BitString
from pyasn1_alt_modules import rfc5280

from pkilint import validation, pkix
from pkilint.itu.bitstring import NamedBitStringMinimalEncodingValidator
from tests import util


def test_non_minimal_named_bitstring_encoding():
    pem = """-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIT3r7MRJB7qx35ms1tFWj7th3y5jANBgkqhkiG9w0BAQ0F
ADAtMSswKQYDVQQDEyJTYW1wbGUgTEFNUFMgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
MCAXDTE5MTEyMDA2NTQxOFoYDzIwNTIwOTI3MDY1NDE4WjAZMRcwFQYDVQQDEw5B
bGljZSBMb3ZlbGFjZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJqV
KfqLwaLjj+gBUCfkacKTg8cc2OtJ9ZSed6U3jUoiZVpMLcP3MUKtLeLg9r1mAfID
lB/wlbdmadXPmrszyidmbuZmOpB5voVQfiLYYy3iOx7YOqzXrl6udP07k0sV+UdS
NRFxrfKeoQEFXgOaGdmnx4OG/e3p1fIKM0dPzZLoOAJF5m5O0xzXPL74zFCWp2f1
ZkuE4A6l41koaZXCN5XL7wWTLMLeNf9Byb5ksKqUuqEHAMd1nmoNMgjY9VfVfcrv
9w43GG8FtpSX+TWzB2zNS2OF+XIVnzRG5DeoULq8v88Z5bLpIJ/nx26r8A4SSwIB
aVv4wPxAf1iPsIVKarUCAwEAAaOBlzCBlDAMBgNVHRMBAf8EAjAAMB4GA1UdEQQX
MBWBE2FsaWNlQHNtaW1lLmV4YW1wbGUwEwYDVR0lBAwwCgYIKwYBBQUHAwQwDwYD
VR0PAQH/BAUDAwcgADAdBgNVHQ4EFgQUolNB1UQ8gCkVfAEj8OeOr83zdw8wHwYD
VR0jBBgwFoAUeF8OWnjYa+RUcD2z3ez38fL6wEcwDQYJKoZIhvcNAQENBQADggEB
AEi3/4eQPCAAbdgVMVbA7CplI+5LIV+7qUrORNdN8E53zu1oBkxktmDPWpQGiGYJ
fsQD2Gu1sz0Ofpqzaw0QHo90ghEcz3GOb9/JFEBRwV8Ern1rHXKRis56PPdBAlTg
3D7QKgwkGolETHH1TFv4mY/XC1CWzWq/wKPActIDt1cujjUKk2ILsa1kqYfbEQol
ZGil0pxx9jdMS5qaTdjb66GvPpkQI1uH4E9xiYbJu5bD+SX0Sgzih79GEhaP8vjc
w6+P//nJ3ExJkVT7OvIJmwGvV0ULtmsghoigcd2BBc/fOKdbyIBmJBe152dd02EW
6FwMfHKDtHO8k+/XBeZcxF0=
-----END CERTIFICATE-----
"""

    decoder = validation.ValidatorContainer(
        validators=[
            pkix.create_extension_decoder({
                rfc5280.id_ce_keyUsage: rfc5280.KeyUsage()
            })
        ]
    )

    validator = NamedBitStringMinimalEncodingValidator()

    util.certificate_test_harness(
        pem,
        validator,
        [
            util.ExpectedResult(
                [validator.VALIDATION_BIT_STRING_NOT_MINIMALLY_ENCODED],
                pdu_supertype=BitString()
            )
        ],
        decoder
    )
