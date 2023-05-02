from pyasn1.type.char import PrintableString
from pyasn1_alt_modules import rfc5280

from pkilint import validation, pkix
from pkilint.itu.string import PrintableStringConstraintValidator
from tests import util


def test_printablestring_has_bad_char():
    pem = """-----BEGIN CERTIFICATE-----
MIIHUDCCBjigAwIBAgIIPyNLlX99xSAwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV
BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRow
GAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRz
LmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1
cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTcxMTAzMTY0NjAxWhcN
MTkxMTAzMTY0NjAxWjCBzzETMBEGCysGAQQBgjc8AgEDEwJDSDEXMBUGCysGAQQB
gjc8AgECEwZUaWNpbm8xHTAbBgNVBA8TFFByaXZhdGUgT3JnYW5pemF0aW9uMRgw
FgYDVQQFEw9DSEURMTAxLjAzMy4xNjExCzAJBgNVBAYTAkNIMQ8wDQYDVQQIEwZU
aWNpbm8xEDAOBgNVBAcTB0NoaWFzc28xFTATBgNVBAoTDFRpY3l3ZWIgU2FnbDEf
MB0GA1UEAxMWd3d3Lm5vbnNvbG9ob3N0aW5nLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALxY4Gw4eLCcOYJnh3eKZUsxOsvMtvf8zKgSlEtzLt2B
o7nZvXy9ShhbMq+K5NP8SFahGom0uYi2CpBGYaVAue2zy+l1CvY6hlmq7moi2/rD
e9Fr4H+i41b5UIQPLAnkd4lpn58LopENbNNkRmCYcjtRtt4/sLYDL6SnB6FK0myO
+6EihOUbLc/qrh7ZLwocNehNxahAnF4/q5Hr7Y40J6UzdtC1Lsi2YGxvkWdiF7BZ
Ri/VR8hILWPiIlnpP/hrm1rBACCeG+C8ogG8CQApnKd2cc7JvzMftDkISjsp9jqq
XbKhsP2g83/h12G+td/aRluYwcuCUfzfMo8aCW07le0CAwEAAaOCA0cwggNDMAwG
A1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA4GA1Ud
DwEB/wQEAwIFoDA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLmdvZGFkZHku
Y29tL2dkaWcyczMtOS5jcmwwXAYDVR0gBFUwUzBIBgtghkgBhv1tAQcXAzA5MDcG
CCsGAQUFBwIBFitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9z
aXRvcnkvMAcGBWeBDAEBMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0
cDovL29jc3AuZ29kYWRkeS5jb20vMEAGCCsGAQUFBzAChjRodHRwOi8vY2VydGlm
aWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvZ2RpZzIuY3J0MB8GA1UdIwQY
MBaAFEDCvSeOzDSDMKIz1/tss/C0LIDOMDUGA1UdEQQuMCyCFnd3dy5ub25zb2xv
aG9zdGluZy5jb22CEm5vbnNvbG9ob3N0aW5nLmNvbTAdBgNVHQ4EFgQUDm4BZh4/
CAhChTtse+YRQT24ymAwggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB2AFYUBpov
18Ls0/XhvUSyPsdGdrm8mRFcwO+UmFXWidDdAAABX4LHrxQAAAQDAEcwRQIhALng
Lec9C13c3N+Z77DM2BD1P3V7XVPfIwMjWd0/Pjy0AiAu6qZMsPzkp2Wa3N9gEciL
YN5v06zCPqGLlzOeFavGfgB2AO5Lvbd1zmC64UJpH6vhnmajD35fsHLYgwDEe4l6
qP3LAAABX4LHs3sAAAQDAEcwRQIgNxnA7ynB3grPmgkTU3DIzvgoV4RaxUbJzb0H
aDrVOt4CIQCDM4nXEZwOS9+d+NPiVytb9haRcONmM7Xq0+lN9lLNpAB2AKS5CZC0
GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAABX4LHta4AAAQDAEcwRQIhAO+i
nki1t0TKUXvxPCz2dKyopkXs1Fm32+zPbeFtqDCcAiBFaF7iieuC5NKwmiKjaPuL
eIuxnWcRYNpemxGVJhXu2TANBgkqhkiG9w0BAQsFAAOCAQEAqajFKL39kE6b6VWl
z5Kf3zAW2fDhlO0J6fegiJdn1aQYLHHfsAYOLVXVsXTdyEHVEP/uZKI/MeNA9ql0
rNj6JHr0RyPOYlRDYmI+o6wvfgO0kUm9aU2pgZJKJ/gcUplUasomPvmMqfw1d5SJ
KfyMa4XW6i/uZtNaDU4qc0coB4ks5VK8xbecgRuxJkCy9PANea35rNz+b5xmNNz3
E7peMK/1ye4OcGrAqa/94RLdqTSvNpk3zbBA4zvSmgOlxKVs3hP87LLneo+B79OC
kRApOcuCyiebYdizN0D7PhNmqsnWvo9cmuMG6hPGvCroAOyEKJAHX5P1WmLYgrrz
C9m2dA==
-----END CERTIFICATE-----
"""

    decoder = validation.ValidatorContainer(
        validators=[
            pkix.create_attribute_decoder({
                rfc5280.id_at_serialNumber: rfc5280.X520SerialNumber()
            }, False)
        ]
    )

    validator = PrintableStringConstraintValidator()

    util.certificate_test_harness(
        pem,
        validator,
        [
            util.ExpectedResult(
                [validator.validations[0]],
                pdu_supertype=PrintableString()
            )
        ],
        decoder
    )
