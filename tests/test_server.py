from http import HTTPStatus
from importlib.metadata import version

import pytest
from fastapi.testclient import TestClient

from pkilint import report, pkix
from pkilint.cabf import serverauth
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.cabf.smime import smime_constants
from pkilint.etsi import etsi_constants
from pkilint.pkix import certificate, ocsp, name, extension, crl
from pkilint.rest import app as web_app


@pytest.fixture()
def app():
    return web_app


@pytest.fixture()
def client(app):
    return TestClient(app)


def test_version(client):
    resp = client.get("/version")
    assert version("pkilint") == resp.json()["version"]


_SMBR_SPONSORED_STRICT_PEM = """-----BEGIN CERTIFICATE-----
MIIGrzCCBJegAwIBAgIUYsQ+Fan+RfQ1ToEaA+PeZh43OTEwDQYJKoZIhvcNAQEL
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
Eqpda1II90v7ae6kNwIPK+140WOhkKilZ526OHvetaZ9XUc=
-----END CERTIFICATE-----"""

_OV_FINAL_CLEAN_PEM = """-----BEGIN CERTIFICATE-----
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
XpOaUjkNSs4=
-----END CERTIFICATE-----"""

_BAD_CERT_POLICIES_DER_PEM = """-----BEGIN CERTIFICATE-----
MIIFxjCCBK6gAwIBAgIQAROrI6zwQH6igXlKWdEvgjANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBE
aWdpQ2VydCBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTAeFw0yMjExMDcwMDAwMDBa
Fw0yMzEyMDcyMzU5NTlaMG4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9y
bmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRgwFgYDVQQKEw9BdGxhc3NpYW4s
IEluYy4xGDAWBgNVBAMMDyouYXRsYXNzaWFuLm5ldDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABAA5f4xySbL2RYn5iN2hWUkfiN1P4SUDSRnXJEUQHXpF8l/END0J
OeR35O6YsNujZ1K4v1jgd9A0IUjZiSv5v0yjggNIMIIDRDAfBgNVHSMEGDAWgBS3
a6LqqKqEjHnqtNoPmLLFlXa59DAdBgNVHQ4EFgQU+mkBUo1ciX5KgAIDvHbxaU2f
7uQwKQYDVR0RBCIwIIIPKi5hdGxhc3NpYW4ubmV0gg1hdGxhc3NpYW4ubmV0MA4G
A1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwgY8G
A1UdHwSBhzCBhDBAoD6gPIY6aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
ZXJ0VExTUlNBU0hBMjU2MjAyMENBMS00LmNybDBAoD6gPIY6aHR0cDovL2NybDQu
ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTUlNBU0hBMjU2MjAyMENBMS00LmNybDAJ
BgNVHSAEAjAAMH8GCCsGAQUFBwEBBHMwcTAkBggrBgEFBQcwAYYYaHR0cDovL29j
c3AuZGlnaWNlcnQuY29tMEkGCCsGAQUFBzAChj1odHRwOi8vY2FjZXJ0cy5kaWdp
Y2VydC5jb20vRGlnaUNlcnRUTFNSU0FTSEEyNTYyMDIwQ0ExLTEuY3J0MAkGA1Ud
EwQCMAAwggF9BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB1AOg+0No+9QY1MudXKLyJ
a8kD08vREWvs62nhd31tBr1uAAABhFR4zfEAAAQDAEYwRAIgc6t8bZ2KunnZ69sG
tr1FwJNkUnziV4paMfwCcUlLt+gCIDQmxKSdxplZkpSC44oGd8ELazQ/pcdt6Cd8
DwGvYHZ6AHYAs3N3B+GEUPhjhtYFqdwRCUp5LbFnDAuH3PADDnk2pZoAAAGEVHjO
GQAABAMARzBFAiBCp50y65Mv9ywP1ZEmtOU5RCaoZnj6FHCYCKRCLiiZhQIhAMVi
1/hXezSaBvGupxA9YK+U+nUvMI9WfNCsF1SCTJkZAHYAtz77JN+cTbp18jnFulj0
bF38Qs96nzXEnh0JgSXttJkAAAGEVHjN0AAABAMARzBFAiBOrjjpLggkFE0tTvs3
sYYMtOnD2hBCtVdrLVkCNggTBQIhAPV5tvqy9MkgEZxT01TCs13BhHfHf+PAAMSI
bqNorCSMMA0GCSqGSIb3DQEBCwUAA4IBAQCSYtQLKmsr3Mm1MiXSrcx5ZLYmNjbV
ngYf1T8+eQWIdSLdHYJwJ4hE44XsRS4F/HBJWldKJyqZ5RUP0fL5KxnH3/7wKD1F
ZjFu9ITmHjNz/55f5BwD7SHi5ZqbT8wYEN1Oy+duFTpeZgJzZFYw8cEIrEYVGrNn
TcujtM2w710EQ+DXIPlXMpMJmtCzzrLzVYdPmIGwiIUoj9BwhgMtBtPInxe7qjm6
B0iBclRQb246wAEPjF/sWAUS+LgmJL2u1CclSWu3h/Ae+yIMKAbdL6Vn5GeLHfCD
kJePcGspl/I0jGLIvpG34YRy9mLrgiWskyETVNFDPIzddBDAqWu2JkDK
-----END CERTIFICATE-----"""

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

_OCSP_RESPONSE_PEM = f"""-----BEGIN OCSP RESPONSE-----\n{_OCSP_RESPONSE_B64}\n-----END OCSP RESPONSE-----\n"""

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

_CRL_PEM = """-----BEGIN X509 CRL-----
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

_CRL_PEM_EXPECT_ERROR = """-----BEGIN X509 CRL-----
MIIBYDBKAgEBMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAoTC0NlcnRzICdyIFVz
Fw0yNDA0MTUxNDMzMDBaFw0yNDA1MTUxNDMzMDBaMAAwDQYJKoZIhvcNAQELBQAD
ggEBAGhq9yTTM2ZjzAxyNvXpVbOI4xQhC0L6pdjsZ13d3QFi41QvRFib13fHgcBm
+hWXFSmOT8qgMlIk74y01DBCmrVyn6mTznr49Vy9k6eBEs34F9EtQrJ5MlYNghX2
8UNNTMbQS/T7aYQuVWp4VRZsM2ZFRC1XxDdj85qraRhhc6fDGS3PS6m5vnRuZlVv
3wVB2N2zutQeZcxHDbAa68rSS3fK8jdKjC8uzbYhCvWYIc/ZUB0c+o9clwbZdkl4
eC6gxZ1/uD98+GilFUdX9JNVsi6Il1x9Upm+Oz6JZ43Ly2+yuQZu2rohZNxEzv/f
rzDRkyHn2a+5mqqc2J9asb6RFUs=
-----END X509 CRL-----"""


def _assert_validationerror_list_present(resp):
    j = resp.json()

    detail_list = j["detail"]
    assert len(detail_list) == 1

    detail_0 = detail_list[0]
    assert detail_0["loc"] == ["body"]
    assert detail_0["type"] == "value_error"
    assert "msg" in detail_0


def test_groups(client):
    resp = client.get("/certificate")
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    names = {lg["name"] for lg in j}
    assert names == {"cabf-serverauth", "cabf-smime", "etsi", "pkix"}


def test_group_no_exist(client):
    resp = client.get("/certificate/foo")
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_group_different_case(client):
    # look at what staring at those tables in 7.1 for days has done to me
    resp = client.get("/certificate/CaBf-SeRveRauTh")

    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    names = {l["name"] for l in j["linters"]}

    assert names == set(
        map(lambda c: c.to_option_str, serverauth_constants.CertificateType)
    )


def test_smime_no_cert(client):
    resp = client.post("/certificate/cabf-smime", json={})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_smime_bad_pem(client):
    resp = client.post("/certificate/cabf-smime", json={"pem": "foo"})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_smime_bad_base64(client):
    resp = client.post("/certificate/cabf-smime", json={"b64": "foo"})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_smime_detect(client):
    resp = client.post(
        "/certificate/cabf-smime", json={"pem": _SMBR_SPONSORED_STRICT_PEM}
    )

    j = resp.json()

    assert (
        j["linter"]["name"]
        == f"{smime_constants.ValidationLevel.SPONSORED}-{smime_constants.Generation.STRICT}"
    )


def test_smime_detect_bad_extension_der(client):
    resp = client.post(
        "/certificate/cabf-smime", json={"pem": _BAD_CERT_POLICIES_DER_PEM}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    _assert_validationerror_list_present(resp)


def test_smime_detect_not_smime(client):
    resp = client.post("/certificate/cabf-smime", json={"pem": _OV_FINAL_CLEAN_PEM})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    _assert_validationerror_list_present(resp)


def test_lint_smime_unknown_linter(client):
    resp = client.post(
        "/certificate/cabf-smime/lint/FOOMASTER-BAR",
        json={"pem": _SMBR_SPONSORED_STRICT_PEM},
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_lint_smime(client):
    resp = client.post(
        "/certificate/cabf-smime/SPONSORED-STRICT",
        json={"pem": _SMBR_SPONSORED_STRICT_PEM},
    )
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert len(j["results"]) == 1

    finding_descriptions = j["results"][0]["finding_descriptions"]
    assert len(finding_descriptions) == 1
    finding_description = finding_descriptions[0]

    assert finding_description["severity"] == "INFO"
    assert (
        finding_description["code"] == "pkix.subject_key_identifier_method_1_identified"
    )


def test_detect_and_lint_smime(client):
    resp = client.post(
        "/certificate/cabf-smime", json={"pem": _SMBR_SPONSORED_STRICT_PEM}
    )
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert (
        j["linter"]["name"]
        == f"{smime_constants.ValidationLevel.SPONSORED.name}-{smime_constants.Generation.STRICT}"
    )

    assert len(j["results"]) == 1

    finding_descriptions = j["results"][0]["finding_descriptions"]
    assert len(finding_descriptions) == 1
    finding_description = finding_descriptions[0]

    assert finding_description["severity"] == "INFO"
    assert (
        finding_description["code"] == "pkix.subject_key_identifier_method_1_identified"
    )


def test_detect_and_lint_smime_with_tls(client):
    resp = client.post("/certificate/cabf-smime", json={"pem": _OV_FINAL_CLEAN_PEM})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    _assert_validationerror_list_present(resp)


def test_serverauth_no_cert(client):
    resp = client.post("/certificate/cabf-serverauth", json={})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_serverauth_bad_pem(client):
    resp = client.post("/certificate/cabf-serverauth", json={"pem": "foo"})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_serverauth_bad_base64(client):
    resp = client.post("/certificate/cabf-serverauth", json={"b64": "foo"})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_serverauth_with_bad_base64_trailer(client):
    resp = client.post(
        "/certificate/cabf-serverauth", json={"b64": _CERT_WITH_TRAILER_B64}
    )
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_serverauth_detect(client):
    resp = client.post(
        "/certificate/cabf-serverauth", json={"pem": _OV_FINAL_CLEAN_PEM}
    )

    j = resp.json()

    assert (
        j["linter"]["name"]
        == serverauth_constants.CertificateType.OV_FINAL_CERTIFICATE.to_option_str
    )


def test_serverauth_detect_not_serverauth(client):
    resp = client.post(
        "/certificate/cabf-serverauth", json={"pem": _SMBR_SPONSORED_STRICT_PEM}
    )
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert (
        j["linter"]["name"]
        == serverauth_constants.CertificateType.DV_FINAL_CERTIFICATE.to_option_str
    )


def test_lint_serverauth_unknown_linter(client):
    resp = client.post(
        "/certificate/cabf-serverauth/FOOMASTER-BAR", json={"pem": _OV_FINAL_CLEAN_PEM}
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_lint_serverauth(client):
    resp = client.post(
        "/certificate/cabf-serverauth/OV-FINAL-CERTIFICATE",
        json={"pem": _OV_FINAL_CLEAN_PEM},
    )
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert len(j["results"]) == 0


def test_detect_and_lint_serverauth(client):
    resp = client.post(
        "/certificate/cabf-serverauth", json={"pem": _OV_FINAL_CLEAN_PEM}
    )
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert (
        j["linter"]["name"]
        == serverauth_constants.CertificateType.OV_FINAL_CERTIFICATE.to_option_str
    )

    assert len(j["results"]) == 0


def test_detect_and_lint_serverauth_with_smime(client):
    resp = client.post(
        "/certificate/cabf-serverauth/", json={"pem": _SMBR_SPONSORED_STRICT_PEM}
    )
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert (
        j["linter"]["name"]
        == serverauth_constants.CertificateType.DV_FINAL_CERTIFICATE.to_option_str
    )


def test_validations_list(client):
    resp = client.get("/certificate/cabf-serverauth/root-ca")
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    v = certificate.create_pkix_certificate_validator_container(
        serverauth.create_decoding_validators(),
        serverauth.create_validators(serverauth_constants.CertificateType.ROOT_CA),
    )

    for actual, expected in zip(j, report.get_included_validations(v)):
        assert actual["code"] == expected.code
        assert actual["severity"] == str(expected.severity)


def test_ocsp_pkix_validations_list(client):
    resp = client.get("/ocsp/pkix")
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    v = ocsp.create_pkix_ocsp_response_validator_container(
        [
            ocsp.create_response_decoder(),
            pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
            pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS),
        ],
        [],
    )

    for actual, expected in zip(j, report.get_included_validations(v)):
        assert actual["code"] == expected.code
        assert actual["severity"] == str(expected.severity)


def test_ocsp_pkix_lint(client):
    resp = client.post("/ocsp/pkix", json={"b64": _OCSP_RESPONSE_B64})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert len(j["results"]) == 0


def test_ocsp_pkix_lint_pem(client):
    resp = client.post("/ocsp/pkix", json={"pem": _OCSP_RESPONSE_PEM})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert len(j["results"]) == 0


def test_ocsp_pkix_lint_b64_in_pem_field(client):
    resp = client.post("/ocsp/pkix", json={"pem": _OCSP_RESPONSE_B64})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_detect_and_lint_etsi(client):
    resp = client.post("/certificate/etsi", json={"pem": _OV_FINAL_CLEAN_PEM})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert (
        j["linter"]["name"]
        == etsi_constants.CertificateType.OVCP_FINAL_CERTIFICATE.to_option_str
    )


def test_crl_pkix_validations_list(
    client, validity_additional_validators=None, doc_additional_validators=None
):
    if doc_additional_validators is None:
        doc_additional_validators = []
    if validity_additional_validators is None:
        validity_additional_validators = []

    resp = client.get("/crl/pkix/crl")
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    v = crl.create_pkix_crl_validator_container(
        [
            pkix.create_attribute_decoder(name.ATTRIBUTE_TYPE_MAPPINGS),
            pkix.create_extension_decoder(extension.EXTENSION_MAPPINGS),
        ],
        [
            crl.create_issuer_validator_container([]),
            crl.create_validity_validator_container(validity_additional_validators),
            crl.create_extensions_validator_container([]),
        ]
        + doc_additional_validators,
    )

    for actual, expected in zip(j, report.get_included_validations(v)):
        assert actual["code"] == expected.code
        assert actual["severity"] == str(expected.severity)


def test_crl_pkix_lint(client):
    resp = client.post("/crl/pkix/crl", json={"b64": _CRL_B64})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert len(j["results"]) == 0


def test_crl_pkix_lint_pem(client):
    resp = client.post("/crl/pkix/crl", json={"pem": _CRL_PEM})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert len(j["results"]) == 0


def test_crl_pkix_lint_b64_in_pem_field(client):
    resp = client.post("/crl/pkix/crl", json={"pem": _CRL_B64})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_crl_pkix_lint_pem_with_error(client):
    resp = client.post("/crl/pkix/crl", json={"pem": _CRL_PEM_EXPECT_ERROR})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert len(j["results"]) == 3


def test_pkix_certificate_group(client):
    resp = client.get("/certificate/pkix")
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert j["linters"][0]["name"] == "certificate"


def test_pkix_certificate_lint(client):
    resp = client.post("/certificate/pkix", json={"pem": _OV_FINAL_CLEAN_PEM})

    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert j["linter"]["name"] == "certificate"

    r = j["results"][0]

    assert (
        r["finding_descriptions"][0]["code"]
        == "pkix.certificate_skid_end_entity_missing"
    )
