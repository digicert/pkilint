import csv
import io
import os
import subprocess
import tempfile

from pkilint.cabf.serverauth import serverauth_constants
from pkilint.cabf.smime import smime_constants


def _test_program_validations(name, args=None):
    if args is None:
        args = []

    output = subprocess.check_output([name, 'validations'] + args).decode()

    s = io.StringIO(output)

    c = csv.DictReader(s)
    row_count = len([r for r in c])

    assert row_count > 0


def test_lint_cabf_serverauth_cert_validations():
    for cert_type in serverauth_constants.CertificateType:
        _test_program_validations('lint_cabf_serverauth_cert', ['-t', cert_type.name.replace('_', '-')])


def test_lint_cabf_smime_cert_validations():
    for g in smime_constants.Generation:
        for v in smime_constants.ValidationLevel:
            _test_program_validations('lint_cabf_smime_cert', ['-t', f'{v}-{g}'])


def test_lint_crl_validations():
    for p in ['BR', 'PKIX']:
        for t in ['CRL', 'ARL']:
            _test_program_validations('lint_crl', ['-p', p, '-t', t])


def test_lint_ocsp_response_validations():
    _test_program_validations('lint_ocsp_response')


def test_lint_pkix_cert_validations():
    _test_program_validations('lint_pkix_cert')


def test_lint_pkix_signer_signee_cert_chain_validations():
    _test_program_validations('lint_pkix_signer_signee_cert_chain')


def test_lint_cabf_serverauth_cert_lint():
    ret = subprocess.run(
        ['lint_cabf_serverauth_cert', 'lint', '-d', '-'],
        input=b"""-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"""
    )

    assert ret.returncode == 0


def test_lint_cabf_smime_cert_lint():
    ret = subprocess.run(
        ['lint_cabf_smime_cert', 'lint', '-g', '-'],
        input=b"""-----BEGIN CERTIFICATE-----
MIIGgDCCBWigAwIBAgIQNr2Tbdy6bU+VjrmujHpQNDANBgkqhkiG9w0BAQsFADBv
MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xRzBFBgNVBAMT
PkRpZ2lDZXJ0IFBLSSBQbGF0Zm9ybSBDMiBTaGFyZWQgU01JTUUgSW5kaXZpZHVh
bCBTdWJzY3JpYmVyIENBMB4XDTIzMDMwOTAwMDAwMFoXDTI1MDMwODIzNTk1OVow
MDEWMBQGA1UEAwwNQ29yZXkgQm9ubmVsbDEWMBQGA1UECgwNRGlnaWNlcnQsIElu
YzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN4WdbzTHQqjkTCru6XZ
nQ7UYS6Mydr+uXb0tlSVdadFj+m8eUv9G437Hbv6VAJxTl2PN+gHTsp5WYAX2QC2
EnfZ+98d4HxsX4/AxB9HXRyfrsuY28k2sQYl/ltPQyAJlI6DMvfj9DtjYkS6kesi
1TLI0IbqV4aw1YrydxOwt51EoSUJdFx4a6FSWSFERjcXp/FVKMruQxGClzRhkgOr
bwD7IVezqRsO+Lu4Skoraf5q7U2aW3BSAcTz9CN/xpI/eJ0gEECjQ21Qk2UYVWi4
R2PyQiDp357vTwdYD1QMKPONN+IGCValRtP+T/W0rZ8dZfMXKBHcrWv1J2sbyfbQ
JS8CAwEAAaOCA1UwggNRMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBYG
A1UdJQEB/wQMMAoGCCsGAQUFBwMEMCUGA1UdEQQeMByBGkNvcmV5LkJvbm5lbGxA
ZGlnaWNlcnQuY29tMIIBIgYDVR0gBIIBGTCCARUwggERBglghkgBhv1sBQIwggEC
MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIHVBggr
BgEFBQcCAjCByBqBxUFueSB1c2Ugb2YgdGhpcyBDZXJ0aWZpY2F0ZSBjb25zdGl0
dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBEaWdpQ2VydCBDUC9DUFMgYW5kIFJlbHlp
bmcgUGFydHkgQWdyZWVtZW50IHdoaWNoIGxpbWl0IGxpYWJpbGl0eSBhbmQgYXJl
IGluY29ycG9yYXRlZCBoZXJlaW4gYnkgcmVmZXJlbmNlLiBodHRwczovL3d3dy5k
aWdpY2VydC5jb20vcnBhLXVhMF0GA1UdHwRWMFQwUqBQoE6GTGh0dHA6Ly9wa2kt
Y3JsLnN5bWF1dGguY29tL2NhXzRiNWQ1ZmQzYjI2NTFiMzUyMjkwZTM2NDZhYmNj
MDAxL0xhdGVzdENSTC5jcmwwfwYIKwYBBQUHAQEEczBxMCgGCCsGAQUFBzABhhxo
dHRwOi8vcGtpLW9jc3AuZGlnaWNlcnQuY29tMEUGCCsGAQUFBzAChjlodHRwOi8v
Y2FjZXIuc3ltYXV0aC5jb20vbXBraS9kaWdpY2VydGMyc2hhcmVkc21pbWVjYS5j
cnQwHwYDVR0jBBgwFoAU3LcfIDF0S5Qadq2Dgq34xqPwRF8wQgYJKoZIhvcNAQkP
BDUwMzAKBggqhkiG9w0DBzALBglghkgBZQMEAQIwCwYJYIZIAWUDBAEWMAsGCWCG
SAFlAwQBKjAtBgpghkgBhvhFARADBB8wHQYTYIZIAYb4RQEQAQICAQGEy9uOSBYG
OTUyMjY4MDkGCmCGSAGG+EUBEAUEKzApAgEAFiRhSFIwY0hNNkx5OXdhMmt0Y21F
dWMzbHRZWFYwYUM1amIyMD0wHQYDVR0OBBYEFF5NZpSDXnDH25XcoXsZvqFS2BBN
MA0GCSqGSIb3DQEBCwUAA4IBAQCQHNrg9EHhTvBJ5drm99rxZCmCQx5AnjuDasDU
XUtRKqy/v1wT8nkNjVceIyzvF6EOd3PPtGJfum+oRe97eRkAk2nlpLL8//vO7GWU
a7lofBAJW1ETVvDVECAoqcdkPHxQM22caTGlJGrd6QGAzMoOAFTDSDhqT3ceiKU4
rdKbtaTErZf73ZWonFxFdz49cJ6AC46NVJPiZmAEAqQVc14q6W4/w9SpWIpxcj6d
vx/vVMi1ilVWDucJYogvEic8X3uCfYBPHTwPHEKvvnXAoJMTTVnJM5CKxVrp09QS
6vmg7EN5ZeFVnjID0GzhfxWBR5/scJCF/s3DGuI0uCCtAruW
-----END CERTIFICATE-----"""
    )

    assert ret.returncode == 5


def test_lint_pkix_cert_lint():
    ret = subprocess.run(
        ['lint_pkix_cert', 'lint', '-'],
        input=b"""-----BEGIN CERTIFICATE-----
MIIGgDCCBWigAwIBAgIQNr2Tbdy6bU+VjrmujHpQNDANBgkqhkiG9w0BAQsFADBv
MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xRzBFBgNVBAMT
PkRpZ2lDZXJ0IFBLSSBQbGF0Zm9ybSBDMiBTaGFyZWQgU01JTUUgSW5kaXZpZHVh
bCBTdWJzY3JpYmVyIENBMB4XDTIzMDMwOTAwMDAwMFoXDTI1MDMwODIzNTk1OVow
MDEWMBQGA1UEAwwNQ29yZXkgQm9ubmVsbDEWMBQGA1UECgwNRGlnaWNlcnQsIElu
YzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN4WdbzTHQqjkTCru6XZ
nQ7UYS6Mydr+uXb0tlSVdadFj+m8eUv9G437Hbv6VAJxTl2PN+gHTsp5WYAX2QC2
EnfZ+98d4HxsX4/AxB9HXRyfrsuY28k2sQYl/ltPQyAJlI6DMvfj9DtjYkS6kesi
1TLI0IbqV4aw1YrydxOwt51EoSUJdFx4a6FSWSFERjcXp/FVKMruQxGClzRhkgOr
bwD7IVezqRsO+Lu4Skoraf5q7U2aW3BSAcTz9CN/xpI/eJ0gEECjQ21Qk2UYVWi4
R2PyQiDp357vTwdYD1QMKPONN+IGCValRtP+T/W0rZ8dZfMXKBHcrWv1J2sbyfbQ
JS8CAwEAAaOCA1UwggNRMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBYG
A1UdJQEB/wQMMAoGCCsGAQUFBwMEMCUGA1UdEQQeMByBGkNvcmV5LkJvbm5lbGxA
ZGlnaWNlcnQuY29tMIIBIgYDVR0gBIIBGTCCARUwggERBglghkgBhv1sBQIwggEC
MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIHVBggr
BgEFBQcCAjCByBqBxUFueSB1c2Ugb2YgdGhpcyBDZXJ0aWZpY2F0ZSBjb25zdGl0
dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBEaWdpQ2VydCBDUC9DUFMgYW5kIFJlbHlp
bmcgUGFydHkgQWdyZWVtZW50IHdoaWNoIGxpbWl0IGxpYWJpbGl0eSBhbmQgYXJl
IGluY29ycG9yYXRlZCBoZXJlaW4gYnkgcmVmZXJlbmNlLiBodHRwczovL3d3dy5k
aWdpY2VydC5jb20vcnBhLXVhMF0GA1UdHwRWMFQwUqBQoE6GTGh0dHA6Ly9wa2kt
Y3JsLnN5bWF1dGguY29tL2NhXzRiNWQ1ZmQzYjI2NTFiMzUyMjkwZTM2NDZhYmNj
MDAxL0xhdGVzdENSTC5jcmwwfwYIKwYBBQUHAQEEczBxMCgGCCsGAQUFBzABhhxo
dHRwOi8vcGtpLW9jc3AuZGlnaWNlcnQuY29tMEUGCCsGAQUFBzAChjlodHRwOi8v
Y2FjZXIuc3ltYXV0aC5jb20vbXBraS9kaWdpY2VydGMyc2hhcmVkc21pbWVjYS5j
cnQwHwYDVR0jBBgwFoAU3LcfIDF0S5Qadq2Dgq34xqPwRF8wQgYJKoZIhvcNAQkP
BDUwMzAKBggqhkiG9w0DBzALBglghkgBZQMEAQIwCwYJYIZIAWUDBAEWMAsGCWCG
SAFlAwQBKjAtBgpghkgBhvhFARADBB8wHQYTYIZIAYb4RQEQAQICAQGEy9uOSBYG
OTUyMjY4MDkGCmCGSAGG+EUBEAUEKzApAgEAFiRhSFIwY0hNNkx5OXdhMmt0Y21F
dWMzbHRZWFYwYUM1amIyMD0wHQYDVR0OBBYEFF5NZpSDXnDH25XcoXsZvqFS2BBN
MA0GCSqGSIb3DQEBCwUAA4IBAQCQHNrg9EHhTvBJ5drm99rxZCmCQx5AnjuDasDU
XUtRKqy/v1wT8nkNjVceIyzvF6EOd3PPtGJfum+oRe97eRkAk2nlpLL8//vO7GWU
a7lofBAJW1ETVvDVECAoqcdkPHxQM22caTGlJGrd6QGAzMoOAFTDSDhqT3ceiKU4
rdKbtaTErZf73ZWonFxFdz49cJ6AC46NVJPiZmAEAqQVc14q6W4/w9SpWIpxcj6d
vx/vVMi1ilVWDucJYogvEic8X3uCfYBPHTwPHEKvvnXAoJMTTVnJM5CKxVrp09QS
6vmg7EN5ZeFVnjID0GzhfxWBR5/scJCF/s3DGuI0uCCtAruW
-----END CERTIFICATE-----"""
    )

    assert ret.returncode == 3


def test_lint_crl_lint():
    ret = subprocess.run(
        ['lint_crl', 'lint', '-t', 'crl', '-p', 'pkix', '-'],
        input=b"""-----BEGIN X509 CRL-----
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
    )

    assert ret.returncode == 0


def test_lint_ocsp_response_lint():
    ret = subprocess.run(
        ['lint_ocsp_response', 'lint', '-'],
        input=b"""MIIDnwoBAKCCA5gwggOUBgkrBgEFBQcwAQEEggOFMIIDgTCBsKIWBBQK46D+ndQl
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
    )

    assert ret.returncode == 0


def test_lint_pkix_signer_signee_cert_chain_lint():
    issuer_f = tempfile.NamedTemporaryFile('w+', delete=False)
    issuer_f.write("""-----BEGIN CERTIFICATE-----
MIIDFjCCAf6gAwIBAgIUF/hP3a/TkmHlfhYYUiFNw/H5lMwwDQYJKoZIhvcNAQEL
BQAwIzELMAkGA1UEBhMCWFgxFDASBgNVBAoMC0NlcnRzICdyIFVzMB4XDTI0MDMy
NTE4NDcwMFoXDTI1MDMyNTE4NDcwMFowIzELMAkGA1UEBhMCWFgxFDASBgNVBAoM
C0NlcnRzICdyIFVzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomfH
KuGQzqGkFGSsKLESgJbRRRQsIuJ19w/sumNHNPnbl93rEgdoF1y2yUFcY0ZipZCg
lIpfhOkp6I+WLtF59t8vLw30P1ZBwmbjC54EwGLH3WRDPS0j+33TfDjNdQRwY4u6
j2EK6drXPhBPsaG0map3VfWQelaStAoIC6evoYFzfO2E7Ik4xv06U47WHefseBue
ZcsFvfW3bf/E04PFc2YssUyqjiaa0sU/w7l9xj2P+vCqpM393ZWJX6GRcns/wUJ/
na7iXpIO82EV3/eExeXoHc912L+m0HoB86RYQat+wyhX6Z5i1ApU6zXqGU7D8cPD
DrbIjwLDMwKPbC9FjwIDAQABo0IwQDAdBgNVHQ4EFgQUtOH2MFQzWu9LjciCbVe+
Th8BB5kwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwDQYJKoZIhvcN
AQELBQADggEBAJGeqkMrzOgesGaCHJJgX/qpG7bp4KPPL0bi7EYnT1cuy5ss053I
Ooh5APYn+GrufWjYn4mwSekvuRTB6VdR4YMeoYPMxWJRp3l7s0aHLo98BbW9WX+4
ju+K/Dndbrs1v7r4IB79hu4QtR7BVaEQ8UjqY+/I1VeYKtAd7scQGKpSNOPN3YVu
+QY3fXy+nfDhj7drUeAHVj+Qz/6RZOIhmIPj7adsZhDQwvMG3cAkAfVGncP7n+cN
nqZyYu8PPQp4g+QM42kXXBu5N8QwkCtcMe2nvKiQvEOZww70N3mTIK8CSxLla5pI
635lNPBZubGF6m35P7EArB0JuU2KYNgUxis=
-----END CERTIFICATE-----""")
    issuer_f.flush()

    subject_f = tempfile.NamedTemporaryFile('w+', delete=False)
    subject_f.write("""-----BEGIN CERTIFICATE-----
MIIDjTCCAnWgAwIBAgIUW8wsCzJEg7WzpMvkUKyloeKqKLYwDQYJKoZIhvcNAQEL
BQAwIzELMAkGA1UEBhMCWFgxFDASBgNVBAoMC0NlcnRzICdyIFVzMB4XDTI0MDMy
NTE4NDcwMFoXDTI1MDMyNTE4NDcwMFowJTELMAkGA1UEBhMCWFgxFjAUBgNVBAoM
DVVubHVja3kgJ3IgV2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6
erJm/+hf6IhoqCYfX+y6uiVSSF/J6VyENk+oXS2g71g1sapGCXRO8xlDqH1rhFzC
IJ56nC14K9w4r+6D3FUKw4G5sKMRTMX7U5brjd8wRd3XHAIUdSCP9SVrNz6bmcjf
B27vBT0ifIC7bQg7Y01BoqnBPObuwT7ufk951rFzCIagzSylzR/GRNhMYo4rO6jw
Ih84LpAxUQ1vFAaBb5GCVhXoUWecu+RtIaIDo9tn8PF16O6VW8zPmsoV9HELD8Sx
HuoSXXcsF2OW55XLeAO+l1tikAVqA6nUvQx03bb3TW7W+3v6nGzG308fHA32TdLk
ZLK9nPnF5hF4pFmWpjwHAgMBAAGjgbYwgbMwHQYDVR0OBBYEFMitbC8lM9mw/hc6
TnvL5vpAyfpZMB8GA1UdIwQYMBaAFLTh9jBUM1rvS43Igm1Xvk4fAQeZMAwGA1Ud
EwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMFMGA1UdHwRMMEowSKAeoByGGmh0dHA6
Ly9mb28uZXhhbXBsZS9jcmwuZGxsoiakJDAiMQswCQYDVQQGEwJYWDETMBEGA1UE
CgwKQ1JMcyAnciBVczANBgkqhkiG9w0BAQsFAAOCAQEAmysx1oqEUDUpLg98K9Rw
AXTykVDjjG0ZKg7UtDcaIeBfomhXv+Sh2oz9zqqZQ5/4HGIwe2fAsbQZmlH//8Yb
ovEZCo3WmhJSyTDB2KLebPJLw5HOi7QrAjYJWKR+pkuQmxMPoSAdMXRkiBmzYjZL
lxHaT6Y2IMZ6kVtHCmcOFaHWJyPAUZ4ymO03cb/1M73ioecf9jMgIf7YBaopty2p
X2GVHaCE1m7u+2WU45b34PBRY/ZvhZvuJKi3TfuaLMJFPz6HY4XbHPnlBP4EwXpC
5VaJvOMXWZPWh/yrCVEKMzFxesbwHV/vyOUls0P4kIY383/78MvzchHLhwR7h2fy
Iw==
-----END CERTIFICATE-----""")
    subject_f.flush()

    ret = subprocess.run(
        ['lint_pkix_signer_signee_cert_chain', 'lint', issuer_f.name, subject_f.name],
    )

    assert ret.returncode == 0

    subject_f.close()
    os.unlink(subject_f.name)

    issuer_f.close()
    os.unlink(issuer_f.name)


def test_exit_code_multiple_256_findings():
    ret = subprocess.run(
        ['lint_cabf_serverauth_cert', 'lint', '-d', '-f', 'csv', '-'],
        input=b"""-----BEGIN CERTIFICATE-----
MIIjSTCCIjGgAwIBAgIKd3d3d3d3d3d3dzANBgkqhkiG9w0BAQsFADBFMQswCQYD
VQQGEwJVUzETMBEGA1UEChMKQ2VydHMgUiBVczEhMB8GA1UEAxMYQ2VydHMgUiBV
cyBJc3N1aW5nIENBIEcxMB4XDTIzMDYwMjAwMDAwMFoXDTI0MDYwMTIzNTk1OVow
ADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJjfM1nBO6c4jF2eL+PP
y+pQOjb+d6eYUk3CypR4j+bzV104d/LT12ukkEL3cR5YapINlZFfMnGxkxz12+AK
1tKo2m8agDlXTeWvl1hS0axCGOGZL16wvR078oxejK2nmfWlUdFhSmWpFyOeuxCG
tTaeqjOHjABvKOwqXNlRTlw0CCQ6j2GFqLGPbJ5yfqGLiDGBB+iVdS8oCQ6RtPks
HH/FNBVeWbwhHE6jrH+yTHbkxJzZwc5W86YHH0PwmsXdCT9gdyfYD1UFm4Ly9iBA
CgUEYbnXEeYmiZV40yDFbwkZ2JvhmtjN4zJpEc4/DP40wMolSZ1F0Gd+2XjJDjSV
iDkCAwEAAaOCIH4wgiB6MB8GA1UdIwQYMBaAFGpOUL+YaJ1beyB11FkBeUhmkjIG
MB0GA1UdEQEB/wQTMBGCD3d3dy5leGFtcGxlLmNvbTAOBgNVHQ8BAf8EBAMCB4Aw
HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDYGA1UdHwQvMC0wK6ApoCeG
JWh0dHA6Ly9jcmwuY2VydHNydXMuY29tL0lzc3VpbmdDQS5jcmwwEwYDVR0gBAww
CjAIBgZngQwBAgEwgh4rBggrBgEFBQcBAQSCHh0wgh4ZMBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBo
dHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwG
CCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8v
dGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUF
BzABhhBodHRwOi8vdGVzdC50ZXN0MBwGCCsGAQUFBzABhhBodHRwOi8vdGVzdC50
ZXN0MDUGCCsGAQUFBzAChilodHRwOi8vY2FjZXJ0cy5jZXJ0c3J1cy5jb20vSXNz
dWluZ0NBLmNydDAMBgNVHRMBAf8EAjAAMIIBfQYKKwYBBAHWeQIEAgSCAW0EggFp
AWcAdwB2/4g/Crb7lVHCYcz1h7o0tKTNuyncaEIKn+ZnTFo6dAAAAYj4va8AAAAE
AwBIMEYCIQCJ6/3b0IBPMTBz2BnztDtEljOplTKLJ+5aLpSnTMi8ngIhAKA5BuMf
FW/zjdC20nLujmm1I/8rikIDoSd0M3jErK8YAHUASLDja9qmRzQP5WoC+p0w6xxS
ActW3SyB2bu/qznYhHMAAAGI+L2vMgAABAMARjBEAiB5qzY/+SKx4S30VxZXnTiF
cOcLigTLzDc7kV4XjQaPNwIgPriQx2hOYEzeBPpy39G0lZM+FAshMq05FD9VRl6y
gxYAdQA7U3d1Pi25gE6LMFsG/kA7Z9hPw/THvQANLXJv4frUFwAAAYj4va8sAAAE
AwBGMEQCIDr0klWCDh0GpiGQw5/1QT4nT9HpWW7VUL6bHgwVSIAFAiBUYnRBYJul
5ex58TJGovCji2tOebCmfGzb1cs6FIMHJzANBgkqhkiG9w0BAQsFAAOCAQEAXff2
RWIifpPcnlpiKzyK8Qabshh3zvk23Oox+La7bed7/lIQIP/WEr/s5H1zxe4s3CU4
358DLBmX93B9oMp+afrHPJl/ZkEAvVhEOtM+OewoOljaoi8UmWC60imeGVT4NIZF
7I3migmd8+8ruaMwDgafRZNwmbZD9S5W0v4XhxnMsJ02Z6R209mD4sa5/PqovuWg
Gcj64YjSspyiNQuoYQm//E5l7u4dn99ZdGYQ2fgBmTfP6smDPGmRsy6d4C7KVr3z
tvwnnut23UJli+glDlKWhsRfHgMbLV2Qh6/eR0eovfk8bt18QqvHp8PzGVidY5hK
eo163oRkEIV75k1Onw==
-----END CERTIFICATE-----""",
        capture_output=True
    )

    out_lines = [l for l in ret.stdout.decode().strip().splitlines() if l]

    assert len(out_lines) == 1 + 256  # header line plus the 256 findings

    assert ret.returncode == 255
