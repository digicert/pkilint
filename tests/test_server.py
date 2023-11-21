import pytest
from http import HTTPStatus
from importlib.metadata import version

from fastapi.testclient import TestClient

from pkilint import report
from pkilint.cabf import serverauth
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.cabf.smime import smime_constants
from pkilint.pkix import certificate
from pkilint.rest import app as web_app


@pytest.fixture()
def app():
    return web_app


@pytest.fixture()
def client(app):
    return TestClient(app)


def test_version(client):
    resp = client.get('/version')
    assert version('pkilint') == resp.json()['version']


_SMBR_SPONSORED_STRICT_PEM = '''-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----'''

_OV_FINAL_CLEAN_PEM = '''-----BEGIN CERTIFICATE-----
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
XpOaUjkNSs4=
-----END CERTIFICATE-----'''

_BAD_CERT_POLICIES_DER_PEM = '''-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
'''


def _assert_validationerror_list_present(resp):
    j = resp.json()

    detail_list = j['detail']
    assert len(detail_list) == 1

    detail_0 = detail_list[0]
    assert detail_0['loc'] == ['body']
    assert detail_0['type'] == 'value_error'
    assert 'msg' in detail_0


def test_groups(client):
    resp = client.get('/certificate')
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    # SMIME and serverauth

    names = {lg['name'] for lg in j}
    assert names == {'cabf-serverauth', 'cabf-smime'}


def test_group_no_exist(client):
    resp = client.get('/certificate/foo')
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_group_different_case(client):
    # look at what staring at those tables in 7.1 for days has done to me
    resp = client.get('/certificate/CaBf-SeRveRauTh')

    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    names = {l['name'] for l in j['linters']}

    assert names == set(map(lambda c: c.to_option_str, serverauth_constants.CertificateType))


def test_smime_no_cert(client):
    resp = client.post('/certificate/cabf-smime', json={})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_smime_bad_pem(client):
    resp = client.post('/certificate/cabf-smime', json={'pem': 'foo'})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_smime_bad_base64(client):
    resp = client.post('/certificate/cabf-smime', json={'b64': 'foo'})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_smime_detect(client):
    resp = client.post('/certificate/cabf-smime', json={'pem': _SMBR_SPONSORED_STRICT_PEM})

    j = resp.json()

    assert j['linter']['name'] == f'{smime_constants.ValidationLevel.SPONSORED}-{smime_constants.Generation.STRICT}'


def test_smime_detect_bad_extension_der(client):
    resp = client.post('/certificate/cabf-smime', json={'pem': _BAD_CERT_POLICIES_DER_PEM})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    _assert_validationerror_list_present(resp)


def test_smime_detect_not_smime(client):
    resp = client.post('/certificate/cabf-smime', json={'pem': _OV_FINAL_CLEAN_PEM})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    _assert_validationerror_list_present(resp)


def test_lint_smime_unknown_linter(client):
    resp = client.post('/certificate/cabf-smime/lint/FOOMASTER-BAR', json={'pem': _SMBR_SPONSORED_STRICT_PEM})
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_lint_smime(client):
    resp = client.post('/certificate/cabf-smime/SPONSORED-STRICT', json={'pem': _SMBR_SPONSORED_STRICT_PEM})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert len(j['results']) == 1

    finding_descriptions = j['results'][0]['finding_descriptions']
    assert len(finding_descriptions) == 1
    finding_description = finding_descriptions[0]

    assert finding_description['severity'] == 'INFO'
    assert finding_description['code'] == 'pkix.subject_key_identifier_method_1_identified'


def test_detect_and_lint_smime(client):
    resp = client.post('/certificate/cabf-smime', json={'pem': _SMBR_SPONSORED_STRICT_PEM})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert (
            j['linter']['name'] ==
            f'{smime_constants.ValidationLevel.SPONSORED.name}-{smime_constants.Generation.STRICT}'
    )

    assert len(j['results']) == 1

    finding_descriptions = j['results'][0]['finding_descriptions']
    assert len(finding_descriptions) == 1
    finding_description = finding_descriptions[0]

    assert finding_description['severity'] == 'INFO'
    assert finding_description['code'] == 'pkix.subject_key_identifier_method_1_identified'


def test_detect_and_lint_smime_with_tls(client):
    resp = client.post('/certificate/cabf-smime', json={'pem': _OV_FINAL_CLEAN_PEM})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    _assert_validationerror_list_present(resp)


def test_serverauth_no_cert(client):
    resp = client.post('/certificate/cabf-serverauth', json={})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_serverauth_bad_pem(client):
    resp = client.post('/certificate/cabf-serverauth', json={'pem': 'foo'})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_serverauuth_bad_base64(client):
    resp = client.post('/certificate/cabf-serverauth', json={'b64': 'foo'})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


def test_serverauth_detect(client):
    resp = client.post('/certificate/cabf-serverauth', json={'pem': _OV_FINAL_CLEAN_PEM})

    j = resp.json()

    assert j['linter']['name'] == serverauth_constants.CertificateType.OV_FINAL_CERTIFICATE.to_option_str


def test_serverauth_detect_not_serverauth(client):
    resp = client.post('/certificate/cabf-serverauth', json={'pem': _SMBR_SPONSORED_STRICT_PEM})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert j['linter']['name'] == serverauth_constants.CertificateType.DV_FINAL_CERTIFICATE.to_option_str


def test_serverauth_detect_bad_extension_der(client):
    resp = client.post('/certificate/cabf-serverauth', json={'pem': _BAD_CERT_POLICIES_DER_PEM})
    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    _assert_validationerror_list_present(resp)


def test_lint_serverauth_unknown_linter(client):
    resp = client.post('/certificate/cabf-serverauth/FOOMASTER-BAR', json={'pem': _OV_FINAL_CLEAN_PEM})
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_lint_serverauth(client):
    resp = client.post('/certificate/cabf-serverauth/OV-FINAL-CERTIFICATE', json={'pem': _OV_FINAL_CLEAN_PEM})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert len(j['results']) == 0


def test_detect_and_lint_serverauth(client):
    resp = client.post('/certificate/cabf-serverauth', json={'pem': _OV_FINAL_CLEAN_PEM})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert j['linter']['name'] == serverauth_constants.CertificateType.OV_FINAL_CERTIFICATE.to_option_str

    assert len(j['results']) == 0


def test_detect_and_lint_serverauth_with_smime(client):
    resp = client.post('/certificate/cabf-serverauth/', json={'pem': _SMBR_SPONSORED_STRICT_PEM})
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    assert j['linter']['name'] == serverauth_constants.CertificateType.DV_FINAL_CERTIFICATE.to_option_str


def test_validations_list(client):
    resp = client.get('/certificate/cabf-serverauth/root-ca')
    assert resp.status_code == HTTPStatus.OK

    j = resp.json()

    v = certificate.create_pkix_certificate_validator_container(
        serverauth.create_decoding_validators(),
        serverauth.create_validators(serverauth_constants.CertificateType.ROOT_CA)
    )

    for actual, expected in zip(j, report.get_included_validations(v)):
        assert actual['code'] == expected.code
        assert actual['severity'] == str(expected.severity)
