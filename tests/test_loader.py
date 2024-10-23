import base64
import tempfile

import pytest

from pkilint import loader, document

_CERT_B64 = """MIIGrzCCBJegAwIBAgIUYsQ+Fan+RfQ1ToEaA+PeZh43OTEwDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCVVMxHzAdBgNVBAoMFkZvbyBJbmR1c3RyaWVzIExpbWl0
ZWQxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAeFw0yMzA0MTkwMDAwMDBaFw0y
MzA3MTgyMzU5NTlaMIGpMSMwIQYDVQRhExpMRUlYRy1BRVlFMDBFS1hFU1ZaVVVF
QlA2NzEeMBwGA1UEChMVQWNtZSBJbmR1c3RyaWVzLCBMdGQuMQ8wDQYDVQQEDAZZ
YW1hZGExDzANBgNVBCoMBkhhbmFrbzEWMBQGA1UEAwwNWUFNQURBIEhhbmFrbzEo
MCYGCSqGSIb3DQEJARYZaGFuYWtvLnlhbWFkYUBleGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALD56BlDp66YkqreF8p8QPh0T+0vgUjm
yOqie30AFUj7UZKrKLVsUGCxGMzRMeWUh0xsqYm1bCcpbwn7k6A03zLpfG/wmYz9
jm9C3aWKzR+peYbxRPPRVNZ2UBdeaFSzqVIAO8Boh7hFWsKxn3svdlBOvJjslFVx
sHiSFQ3canTKD7zTVJfOgVNNr5QYhEsTrqMfnVprlVe732Ge/U6Ify1CuN2LyYfq
4b+Jyrhe4h41YwXfbAeog44+9BxZXczkPa/EkSPvTYq7qT05BeQCjXupFISidZbg
e0tu2ZLwd7Uk09z+fd1VSb58zo2gNc+gs/uPnkb3MrKoa0YBZcCPUxMCAwEAAaOC
Ai0wggIpMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQYMBaA
FNZEADJ8qA3/rE9rZu61rpssxThUMB0GA1UdDgQWBBSJGVleDvFp9cu9R+E0/OKY
zGkwkTAUBgNVHSAEDTALMAkGB2eBDAEFAwMwPQYDVR0fBDYwNDAyoDCgLoYsaHR0
cDovL2NybC5jYS5leGFtcGxlLmNvbS9pc3N1aW5nX2NhX2NybC5jcmwwSwYIKwYB
BQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vcmVwb3NpdG9yeS5jYS5leGFt
cGxlLmNvbS9pc3N1aW5nX2NhLmRlcjATBgNVHSUEDDAKBggrBgEFBQcDBDCB2AYD
VR0RBIHQMIHNgRloYW5ha28ueWFtYWRhQGV4YW1wbGUuY29toCYGCCsGAQUFBwgJ
oBoMGOWxseeUsOiKseWtkEBleGFtcGxlLmNvbaSBhzCBhDEjMCEGA1UEYRMaTEVJ
WEctQUVZRTAwRUtYRVNWWlVVRUJQNjcxJDAiBgNVBAoMG+OCouOCr+ODn+W3peal
reagquW8j+S8muekvjEPMA0GA1UEBAwG5bGx55SwMQ8wDQYDVQQqDAboirHlrZAx
FTATBgNVBAMMDOWxseeUsOiKseWtkDAjBgkrBgEEAYOYKgEEFhMUQUVZRTAwRUtY
RVNWWlVVRUJQNjcwEgYJKwYBBAGDmCoCBAUTA0NFTzANBgkqhkiG9w0BAQsFAAOC
AgEAE/8rQdESC9lQcnw5TnIj/DhzWqrE6S4I1F7LFgUNQB5GJUSUbnFdeExwfV+t
bjloht4frY7oJvvYyjT2t5/nv2Hrfpe95KmRhliEkEfs3ri5J/pMHa5ju1Kox49n
m8OjKkon9HMK6c7IJy2Ow1yrwDYDflVeMmZUvMr+EmUk6BdRtF40ljNwLw8xJZfh
xUzo1OjaTKu7gtYqzrFhEqijpVoxtWIBLgL7IAujPYONrxeffJ7DY6vWzBVG4C+7
iuqlrf6Y2f25yfEp0Hs9kBD26xEZUg43Zl7BxaBbJLesUk2FRD1B/N5DYZecTc7W
F1a1YUW5N15wskn8SZAXIz9xx8OThu9v7eP3qpUNaU+iaTqbjxTPGiSUYa3Jrm1y
Abh4XCOUfb4UJo23uHsNZyoLOX8lVOsesLOE/BGvlKHzT0x49uNKZq0O6lU9fxFt
iM4MRNqmNZTN9jZ1yu06cuI8nr8AEWt7Hp5OTldj5KXZFd945DqWyZHx01Uv/w5Z
U8/E3Jf1bDTbf5OLWqombrgLIWL+A/SrRvnqyLpyDv2PHJ0IgbsylDRalxeGHa1Q
3egwHqkYRzYOy3LYRphJITSGCnqRGshySonks4osE7KbXFwMEEmEWlF1S7S+VDkq
Eqpda1II90v7ae6kNwIPK+140WOhkKilZ526OHvetaZ9XUc="""


_CERT_WITH_TRAILER_B64 = """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
p6o9EaAJgzlOHGRsk5NZTCZkXpOaUjkNSs5B"""


_OCSP_RESPONSE_B64 = """MIIDnwoBAKCCA5gwggOUBgkrBgEFBQcwAQEEggOFMIIDgTCBsKIWBBQK46D+ndQl
dpi163Lrygznvz318RgPMjAyNDA0MDIxMjM3NDdaMIGEMIGBMFkwDQYJYIZIAWUD
BAIBBQAEIDqZRndWgHOnB7/eUBhjReTNYTTbCF66odEEJfA7bwjqBCBHSmyjAfI9
yff3B4cE4cf1/JbnFnX27YguerZcP1hFQwIEAarwDYAAGA8yMDI0MDQwMzEyMzc0
N1qgERgPMjAyNDA0MTAxMjM3NDdaMAoGCCqGSM49BAMDA2kAMGYCMQDRmVmiIb4D
m9yEXiv2XtoeQi6ftpjLmlBqqRIi+3htfF/OyjdHnFuh38cQKYqqrWYCMQDKiPct
Vu7SQs587d2ZBEHQH20j5AFiGGsbI1b3+C9ZK6NIzgD6DnWlDwpSfilEarOgggJT
MIICTzCCAkswggGuoAMCAQICAQEwCgYIKoZIzj0EAwQwODELMAkGA1UEBhMCWFgx
FDASBgNVBAoMC0NlcnRzICdyIFVzMRMwEQYDVQQDDApJc3N1aW5nIENBMB4XDTI0
MDQwMjEyMzc0N1oXDTI1MDQwMjEyMzc0N1owPDELMAkGA1UEBhMCWFgxFDASBgNV
BAoMC0NlcnRzICdyIFVzMRcwFQYDVQQDDA5PQ1NQIFJlc3BvbmRlcjB2MBAGByqG
SM49AgEGBSuBBAAiA2IABFsJAbiFIyluuRnVD/oanLN0vE1AlYYoK/7KEbHZWtu1
RzSvVwv4K3IozyJrz0wl3bz+Oxo605Qw7/dj4daNLhUdkXILd5W1jaazRjlhOo+5
tajaSMZ0cRf5kZ6EJPN+yKOBhzCBhDAdBgNVHQ4EFgQUCuOg/p3UJXaYtety68oM
57899fEwHwYDVR0jBBgwFoAUjsIUCWB26pA46TmuG21SxBd9n74wDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwDwYJKwYB
BQUHMAEFBAIFADAKBggqhkjOPQQDBAOBigAwgYYCQRQqjNYKbGXHdGXfEVvB//i+
DiG02hraU9kGNKXeiQcPdZRajQsY/hdZPVyaykkAFVQGv29yWmTrEax+r4oZTtzG
AkFJCwtJpi7m00Qx9r/ugNWsnCFSiKUdxuvj7mg9lJtz0hexRJZKFODWJG5dUh//
Bc2w8vywgYYoduXu4QLcoP17CA=="""


_CRL_B64 = """MIIBzTCBtgIBATANBgkqhkiG9w0BAQsFADAiMQswCQYDVQQGEwJYWDETMBEGA1UE
CgwKQ1JMcyAnciBVcxcNMjQwMzI1MTg0NzAwWhcNMjQwNDAxMTg0NzAwWqBgMF4w
CgYDVR0UBAMCAQEwHwYDVR0jBBgwFoAU/NE0t8uklbG2WeoLBWIe6JqPtDowLwYD
VR0cAQH/BCUwI6AeoByGGmh0dHA6Ly9mb28uZXhhbXBsZS9jcmwuZGxshAH/MA0G
CSqGSIb3DQEBCwUAA4IBAQAN8oDSvWsg3JvUJ4MkXvczaFb72VH0J/VL5PV2cBSm
MfaVBKnUsNr1IcxT06KF8gNrDTpKqJ9fetO290swZfcPt9sEVUBVQUpdlQc3tya1
jYWmFkA3tkpqH5rBCQa3CBm1Cg8cbFBtwWgWr70NsVvfD6etjAEP9Ze+MSXnGV0p
w9EeOV07HnSD/PGQwqCiaSn5DdIDVoH8eFSGmgNLw+b4SwUjmz8PqsZwvHxJvleV
1D8cj7zdR4ywgRMjEfJZ8Bp+Tdu64Gv0doDS0iEJIshLHYkcW1okpq/tPm8kKAbD
reparePNQwhScVcDiSL73eEBIPokgG3QhohiucP5MeF1"""


def _make_pem(b64, pem_label):
    return f"-----BEGIN {pem_label}-----\n{b64}\n-----END {pem_label}-----"


def _load_and_compare(loader_func, expected_doc_cls, expected_substrate):
    loaded = loader_func()

    assert isinstance(loaded, expected_doc_cls)
    assert loaded.substrate == expected_substrate


def _test_loader_obj(loader_instance, doc_b64):
    doc_cls = loader_instance._document_cls
    label = loader_instance._document_pem_label

    doc_pem = _make_pem(doc_b64, label)
    doc_der = base64.b64decode(doc_b64)

    _load_and_compare(
        lambda: loader_instance.load_b64_document(doc_b64, "test"), doc_cls, doc_der
    )
    _load_and_compare(
        lambda: loader_instance.load_pem_document(doc_pem, "test"), doc_cls, doc_der
    )
    _load_and_compare(
        lambda: loader_instance.load_der_document(doc_der, "test"), doc_cls, doc_der
    )
    _load_and_compare(
        lambda: loader_instance.load_document(doc_b64, "test"), doc_cls, doc_der
    )
    _load_and_compare(
        lambda: loader_instance.load_document(doc_pem, "test"), doc_cls, doc_der
    )
    _load_and_compare(
        lambda: loader_instance.load_document(doc_der, "test"), doc_cls, doc_der
    )
    _load_and_compare(
        lambda: loader_instance.load_document_or_file(doc_b64, "test"), doc_cls, doc_der
    )
    _load_and_compare(
        lambda: loader_instance.load_document_or_file(doc_pem, "test"), doc_cls, doc_der
    )
    _load_and_compare(
        lambda: loader_instance.load_document_or_file(doc_der, "test"), doc_cls, doc_der
    )

    # format-specific file load
    with tempfile.TemporaryFile("w+") as f:
        f.write(doc_b64)

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_b64_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+b") as f:
        f.write(doc_b64.encode())

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_b64_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+") as f:
        f.write(doc_pem)

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_pem_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+b") as f:
        f.write(doc_pem.encode())

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_pem_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+b") as f:
        f.write(doc_der)

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_der_file(f, "test"), doc_cls, doc_der
        )

    # format-agnostic load
    with tempfile.TemporaryFile("w+") as f:
        f.write(doc_b64)

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+b") as f:
        f.write(doc_b64.encode())

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+") as f:
        f.write(doc_pem)

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+b") as f:
        f.write(doc_pem.encode())

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+b") as f:
        f.write(doc_der)

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_file(f, "test"), doc_cls, doc_der
        )

    # format-agnostic file or document load
    with tempfile.TemporaryFile("w+") as f:
        f.write(doc_b64)

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_document_or_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+b") as f:
        f.write(doc_b64.encode())

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_document_or_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+") as f:
        f.write(doc_pem)

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_document_or_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+b") as f:
        f.write(doc_pem.encode())

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_document_or_file(f, "test"), doc_cls, doc_der
        )

    with tempfile.TemporaryFile("w+b") as f:
        f.write(doc_der)

        f.flush()
        f.seek(0)

        _load_and_compare(
            lambda: loader_instance.load_document_or_file(f, "test"), doc_cls, doc_der
        )


def test_certificate_loader():
    _test_loader_obj(loader._RFC5280_CERTIFICATE_LOADER_INSTANCE, _CERT_B64)


def test_crl_loader():
    _test_loader_obj(loader._RFC5280_CERTIFICATE_LIST_LOADER_INSTANCE, _CRL_B64)


def test_ocsp_response_loader():
    _test_loader_obj(loader._RFC6960_OCSP_RESPONSE_LOADER_INSTANCE, _OCSP_RESPONSE_B64)


def test_load_cert_with_trailer():
    with pytest.raises(document.SubstrateDecodingFailedError):
        loader.load_der_certificate(
            base64.b64decode(_CERT_WITH_TRAILER_B64), "test", "test"
        )
