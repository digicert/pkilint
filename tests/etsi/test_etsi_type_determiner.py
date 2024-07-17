from pkilint import etsi
from pkilint import loader
from pkilint.etsi.etsi_constants import CertificateType


def _assert_pem_is_certificate_type(expected_type, pem):
    cert = loader.load_certificate(pem, 'pem')

    assert etsi.determine_certificate_type(cert) == expected_type


def test_qevcp_w_non_eidas_certificate_type():
    _assert_pem_is_certificate_type(CertificateType.QEVCP_W_NON_EIDAS_PRE_CERTIFICATE,
                                    '''-----BEGIN CERTIFICATE-----
MIIHfTCCBWWgAwIBAgIMFzle8tVI5MLthWVyMA0GCSqGSIb3DQEBCwUAMFkxCzAJ
BgNVBAYTAkdCMRswGQYDVQQKExJHTU8gR2xvYmFsU2lnbiBMdGQxLTArBgNVBAMT
JEdsb2JhbFNpZ24gR0NDIFIzIFVLIEVWIFFXQUMgQ0EgMjAyMDAeFw0yMzA2MTYw
ODMzMzRaFw0yNDA2MTUwODMzMzNaMIHyMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2Fu
aXphdGlvbjEVMBMGA1UEBRMMMDQ1OS4xMzQuMjU2MRMwEQYLKwYBBAGCNzwCAQMT
AkJFMQswCQYDVQQGEwJCRTEXMBUGA1UECAwOVmxhYW1zLUJyYWJhbnQxDzANBgNV
BAcMBkxldXZlbjEXMBUGA1UECQwORGllc3RzZXZlc3QgMTQxFjAUBgNVBAoMDUds
b2JhbFNpZ24gTlYxIDAeBgNVBAMMF3d3dy5nbG9iYWxzaWduLWRlbW8uY29tMRsw
GQYDVQRhDBJOVFJCRS0wNDU5LjEzNC4yNTYwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCpn0FCPXqC0Lx5clF4Qq4ez3CW3iLRJegKqMaD84PN504skXsY
bDhLz+naT3naIqsYJUV9A+b01BRVgMR4vZpZ27EY28tRwRf9s7eImzO5QXFPoG+i
2ztRC7rE4Q33HO5SRKp3ZEV9Es8fW3/mJxGrLFJuS7c6sX0bU/dBdISw1j0pM/8+
oXN0Kiy/vcMULkP/eL6nmj45jklIFoRxb0AZzemQijj+t8fz8bLWZISLBzvqmL0Y
hjpCkLnyjgVM5xtElSPf7/a7J7jnaleZ3gJhxYF+FndyHooaBAHxFA32BmSgV3PD
Rgq3eLMUGrngSlGNXbTWMxnUTh93lrqiturXAgMBAAGjggKpMIICpTBEBgNVHR8E
PTA7MDmgN6A1hjNodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjN1a2V2
cXdhY2NhMjAyMC5jcmwwPQYIKwYBBQUHAQMEMTAvMAgGBgQAjkYBATATBgYEAI5G
AQYwCQYHBACORgEGAzAOBgYEAI5GAQcwBBMCR0IwgZkGCCsGAQUFBwEBBIGMMIGJ
MEkGCCsGAQUFBzAChj1odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2Vy
dC9nc2djY3IzdWtldnF3YWNjYTIwMjAuY3J0MDwGCCsGAQUFBzABhjBodHRwOi8v
b2NzcC5nbG9iYWxzaWduLmNvbS9nc2djY3IzdWtldnF3YWNjYTIwMjAwgacGA1Ud
IASBnzCBnDBBBgkrBgEEAaAyAQEwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cu
Z2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wBwYFZ4EMAQEwCQYHBACL7EABBDBD
BgsrBgEEAaAyASwoATA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
aWduLmNvbS9yZXBvc2l0b3J5LzAiBgNVHREEGzAZghd3d3cuZ2xvYmFsc2lnbi1k
ZW1vLmNvbTAiBgVngQwDAQQZMBcTA05UUhMCQkUMDDA0NTkuMTM0LjI1NjAMBgNV
HRMBAf8EAjAAMB8GA1UdIwQYMBaAFAeUNkpRlUn97ioGeTZ/wjc7Ttu/MB0GA1Ud
JQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4EFgQUzAkXOmPl1fx/NWnn
M2kcUxBAZ5QwDgYDVR0PAQH/BAQDAgeAMBMGCisGAQQB1nkCBAMBAf8EAgUAMA0G
CSqGSIb3DQEBCwUAA4ICAQCaXlFvQuIgDR/2ARtUwmknMv2K0hARJ8jIXp+uiOoy
EejR2HZetKOKKXdLZVeFHAV1gujMujStu7zu/weqnoACLLPyZfizxT1CpImPOorv
YDzKWOJWz22Dwg7uxk5HuFmxVla2mru12bdQho0JDmsldMJlc7Mq3S7Q88AOUkmi
roaSEsQ+joZ4NILZtcl2rkD2U/aTOBkUh80CJpyZP8QHD16ztD9sWmBtRtHRnCAd
xbZAkKAq3VQ/qCYT7OkTcui2xh327ZPwmNJiYILJ5vRIheiZIuj31x3FkmXus/f8
nTX/p1MmDn1sx2vpuyQ5vGyX8knXyfwqe1NiNKq0QT+1bqLggT2Li21S9XavwFcl
x6IuRDlBFWMgJTGPgn2ZIpzmsfOxeCvQAKJWVdvGgDItRPSGnAs3WHeSmQPobW8Q
m/LareZcoDwUBT70C6EMm6cc9C2XVDHPs5wW9eIWL8IF1Jd03tXIIDIfuIHnFX3o
/UCkHCCN4nQSIp57CI8Z5mDbpj3G0jEAnJyYGTPXR6MugsSuY8tTYIyN2y0qXzYx
w8PRAMBKq4f+ZYAHj/I54QT/Rvj2Wyhna9QNBvjWgImHPEDrIZ4MGlTeJuL7WjsQ
hfQZjQ3aw24SEg51Sf1UTQ80xAZJoK8Q3kTzymzUZgqeutUtYrTgXjzd4Mv+52YQ
oQ==
-----END CERTIFICATE-----''')


def test_qevcp_w_psd2():
    _assert_pem_is_certificate_type(CertificateType.QEVCP_W_PSD2_EIDAS_PRE_CERTIFICATE, '''-----BEGIN CERTIFICATE-----
MIIH4DCCBcigAwIBAgIUZ2W0z0CUqkRQtqh+2ZeuUOubCNswDQYJKoZIhvcNAQEL
BQAwVzELMAkGA1UEBhMCTkwxIDAeBgNVBAoMF1F1b1ZhZGlzIFRydXN0bGluayBC
LlYuMSYwJAYDVQQDDB1RdW9WYWRpcyBRdWFsaWZpZWQgV2ViIElDQSBHMjAeFw0y
NDAxMDUxMjM2MzRaFw0yNTAxMDUxMjMxMDBaMIIBEjETMBEGCysGAQQBgjc8AgED
EwJERTEXMBUGCysGAQQBgjc8AgECDAZCYXllcm4xGTAXBgsrBgEEAYI3PAIBAQwI
QXVnc2J1cmcxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRAwDgYDVQQF
EwdHblIgNjEyMQswCQYDVQQGEwJERTEPMA0GA1UECAwGQmF5ZXJuMRAwDgYDVQQH
DAdIdXJsYWNoMRswGQYDVQRhDBJQU0RERS1CQUZJTi0xMDY2NTMxJTAjBgNVBAoM
HFJhaWZmZWlzZW5iYW5rIFNpbmdvbGR0YWwgZUcxIjAgBgNVBAMMGXhzMmFwc2Qy
LnJiLXNpbmdvbGR0YWwuZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDRyGepEOvd+8o7fOluGGj3NwnardkJ+jEnBHtcqF1boA70AoFs2a+MLPF9eoif
5FjS9EtYwaFzgZN2XqkbKvCes612jsXBHLeYlOahBjZOtTlCjA5NBs+sgZWaVTBQ
5YPGsYImEAiRrUqtTY6+gGiWKKfbD7y6p8kywJhO++bawKYBnjTdxhMm0SS4cRBl
Fw/vzjRXXg7up3mpOFlYlvsIb53Dzl+DnpuPg/xBuVJXSdmG6MbzV3LHSaCsN4qy
75pDDyIQj0UU0HJ/A0XIB434NQkOlfrVCx9aa4hxM+qm754Y9tvuPiNJy74cCKBT
/uqpXx1Ao017yf9pcbGKweoZAgMBAAGjggLlMIIC4TAfBgNVHSMEGDAWgBS86177
2A3ogq6GRr07fLJv0Sx/CjCBhQYIKwYBBQUHAQEEeTB3MEkGCCsGAQUFBzAChj1o
dHRwOi8vdHJ1c3QucXVvdmFkaXNnbG9iYWwuY29tL3F1b3ZhZGlzcXVhbGlmaWVk
d2ViaWNhZzIuY3J0MCoGCCsGAQUFBzABhh5odHRwOi8vb2NzcC5xdW92YWRpc2ds
b2JhbC5jb20wJAYDVR0RBB0wG4IZeHMyYXBzZDIucmItc2luZ29sZHRhbC5kZTB/
BgNVHSAEeDB2MAkGBwQAi+xAAQQwCQYHBACBmCcDATAOBgwrBgEEAb5YAAJkAQIw
RQYKKwYBBAG+WAGDQjA3MDUGCCsGAQUFBwIBFilodHRwczovL3d3dy5xdW92YWRp
c2dsb2JhbC5jb20vcmVwb3NpdG9yeTAHBgVngQwBATAdBgNVHSUEFjAUBggrBgEF
BQcDAgYIKwYBBQUHAwEwgbkGCCsGAQUFBwEDBIGsMIGpMAoGCCsGAQUFBwsCMAgG
BgQAjkYBATATBgYEAI5GAQYwCQYHBACORgEGAzA7BgYEAI5GAQUwMTAvFilodHRw
czovL3d3dy5xdW92YWRpc2dsb2JhbC5jb20vcmVwb3NpdG9yeRMCZW4wPwYGBACB
mCcCMDUwAAwnRmVkZXJhbCBGaW5hbmNpYWwgU3VwZXJ2aXNvcnkgQXV0aG9yaXR5
DAhERS1CQUZJTjAiBgVngQwDAQQZMBcTA1BTRBMCREUMDEJBRklOLTEwNjY1MzBM
BgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLnF1b3ZhZGlzZ2xvYmFsLmNvbS9x
dW92YWRpc3F1YWxpZmllZHdlYmljYWcyLmNybDAdBgNVHQ4EFgQU0CDt76mzymMP
mVDWONHd8j8htIowDgYDVR0PAQH/BAQDAgWgMBMGCisGAQQB1nkCBAMBAf8EAgUA
MA0GCSqGSIb3DQEBCwUAA4ICAQAgxCKTQCShhgmSJHgV2nBz12jxB4Tl2NIxfmFm
XGrrzOYbN7+s0rkRW5srtRCRjy4MQlVuaI1zpNvKqmZ8K1YXvIaQbHcnmptNsvje
rjcG8sbQqBxsRwZ87nB8QQ1Hb+2rUD4jpKXjYhTn4+LBKUGqvuvoxa1h5Ojl13c0
nzPmtsVk6MvYyE+dOscmeF2L7+CAEMrGtfvVMj4QqWUDUHmBbDG0gTu/lAE3rB0U
KT8B5tHI6zEsEet3ySx8QZ0CfLyln37JfxlSMVkU0Kyt2AjqlV9QpoaiAZq++Vpf
vGB1JenDiBYXbO0VNdRuCNC8F++CsgWsqvqdfUlnQGt+9lYSikLHeRpJzr0GwOJc
OuiFXKMWV22sCQizr2xQCWS9ajbROVaFFsViIoBlK1GykMTZWzHI13f120OUbMZ9
5wnmCxej8aRZXKuZXg+I6ztu0Wm2tjlHb9hfZnuiTviitveDxpM8tX8+6eDWlFqC
ZcrLZUy7r4ZdU0dSRsYx2WDRcIuHcQ593VzM8XBYPtYZ7z8cMlzkRr/fUpjWtujH
1joq8HiMKZaMqLBhS1cyiEaSCv99MRqxq2UT58HanAJ2St/1u6UVbXJ39VXpRtWZ
3IjZc9mgkHoOf1h1VLc2DSoWSjfWabjbDH2rBLRNywStpQhSjAdeSeiUPTE7wz6N
yrv/BQ==
-----END CERTIFICATE-----''')


def test_qncp_w_ov_eidas_final_certificate():
    _assert_pem_is_certificate_type(CertificateType.QNCP_W_OV_EIDAS_FINAL_CERTIFICATE, '''-----BEGIN CERTIFICATE-----
MIIH4zCCBsugAwIBAgIQT8EQTyw0XlFlsnajhgndxTANBgkqhkiG9w0BAQsFADBH
MQswCQYDVQQGEwJFUzERMA8GA1UECgwIRk5NVC1SQ00xJTAjBgNVBAsMHEFDIENv
bXBvbmVudGVzIEluZm9ybcOhdGljb3MwHhcNMjQwMTI1MTQ1NjM1WhcNMjUwMTI1
MTQ1NjM1WjB5MQswCQYDVQQGEwJFUzEPMA0GA1UEBwwGTUFEUklEMQ0wCwYDVQQK
DARGTk1UMRIwEAYDVQQFEwlRMjgyNjAwNEoxGDAWBgNVBGEMD1ZBVEVTLVEyODI2
MDA0SjEcMBoGA1UEAwwTcHJvdmVlZG9yZXMuZm5tdC5lczCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAJ0gVvo9+5v6TneKbairT1fMHTvHhdV7aZ6ID/UK
gnM73+hBv0LK1/xdp3uhug5QUiPUlrcI0LknK7xuvVUjpc4bMwBJd1xZpztAOsIM
hAM8xvvPXAaTUHW5WUNvjj0USTGLkC1guAmQm7VbHW6umAYZKbru4sv8aUQGf166
z7pcQ7wwLhpk5sMCN1uJ04TuAIm71rTAdRfNnuZaPsMXgFgQ/HlY4Ufv0P6N3GEr
SkVj9JMnvMnN5hLZ1EiFzQn7m/nuHwVY9Z3koY7+yLGSzYB/2zZuecV/tVxsesOF
aCZ0UyXZUx7FpegI1PyPOTDg8RkHV0aNVg5eKgDQoAvMirMCAwEAAaOCBJcwggST
MAwGA1UdEwEB/wQCMAAwgYEGCCsGAQUFBwEBBHUwczA7BggrBgEFBQcwAYYvaHR0
cDovL29jc3Bjb21wLmNlcnQuZm5tdC5lcy9vY3NwL09jc3BSZXNwb25kZXIwNAYI
KwYBBQUHMAKGKGh0dHA6Ly93d3cuY2VydC5mbm10LmVzL2NlcnRzL0FDQ09NUC5j
cnQwWQYDVR0gBFIwUDAIBgZngQwBAgIwOQYKKwYBBAGsZgMJFTArMCkGCCsGAQUF
BwIBFh1odHRwOi8vd3d3LmNlcnQuZm5tdC5lcy9kcGNzLzAJBgcEAIvsQAEFMB4G
A1UdEQQXMBWCE3Byb3ZlZWRvcmVzLmZubXQuZXMwHQYDVR0lBBYwFAYIKwYBBQUH
AwEGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQU33VouFQ+JLbJ
QqUjq0Wc2MFmt44wgbAGCCsGAQUFBwEDBIGjMIGgMAsGBgQAjkYBAwIBDzATBgYE
AI5GAQYwCQYHBACORgEGAzByBgYEAI5GAQUwaDAyFixodHRwczovL3d3dy5jZXJ0
LmZubXQuZXMvcGRzL1BEU19DT01QX2VzLnBkZhMCZXMwMhYsaHR0cHM6Ly93d3cu
Y2VydC5mbm10LmVzL3Bkcy9QRFNfQ09NUF9lbi5wZGYTAmVuMAgGBgQAjkYBATAf
BgNVHSMEGDAWgBQZ+FgvFNamzJsEmAgNTNerAKeDZTCB4AYDVR0fBIHYMIHVMIHS
oIHPoIHMhoGebGRhcDovL2xkYXBjb21wLmNlcnQuZm5tdC5lcy9DTj1DUkwxLE9V
PUFDJTIwQ29tcG9uZW50ZXMlMjBJbmZvcm1hdGljb3MsTz1GTk1ULVJDTSxDPUVT
P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q7YmluYXJ5P2Jhc2U/b2JqZWN0Y2xh
c3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGKWh0dHA6Ly93d3cuY2VydC5mbm10LmVz
L2NybHNjb21wL0NSTDEuY3JsMIIBfQYKKwYBBAHWeQIEAgSCAW0EggFpAWcAdQBO
daMnXJoQwzhbbNTfP1LrHfDgjhuNacCx+mSxYpo53wAAAY1BH3FbAAAEAwBGMEQC
IGsslwqMkiUDk8htgr60ujXKWCUrb6AhSbsP7l0eDz7rAiBnZz5wQMd6XYgQqWOz
vUGDXy3IZFp5G6EkRoTt2d9S/QB2AM8RVu7VLnyv84db2Wkum+kacWdKsBfsrAHS
W3fOzDsIAAABjUEfcm4AAAQDAEcwRQIgJmWKkBUv4wqEpwZjWfXh3w7CR2E3B9la
u3U8HRNsZ8UCIQCEKx5A0ipdT5uVneF6V9Lcv+u27TpxXR2HvZ2OT0oNQQB2ABNK
3xq1mEIJeAxv70x6kaQWtyNJzlhXat+u2qfCq+AiAAABjUEfc3QAAAQDAEcwRQIg
KHbPdFZwtApBW3e1kmdm5thTEsPli9TnTKB5SwTi0hICIQCDj5GWTjuhPG81kszs
jNiaKn0EFVXnPG4TNV3D9Thm3zANBgkqhkiG9w0BAQsFAAOCAQEAQdSrj4jTi3vA
yM7XTSYMFhRHIGVfIMeJ3it1rugyNjhg9dUZsAIozdOlFLyKNNTTk4xOpIwUYz3Q
uW7NntGHECR0M6HBiKg8fxLSjC728o1/DpFcmJE4h3mvNcQh5cC2JtwHG05HPgjk
/N+BPq69xDs5QnqH9QUwX3TRkyM6O8hqNyUIHdKQRnvAmxLwZzEnR3KsnZ4LtmPd
sLcGGRTmBRY8tG32VsdbwFaIH2tX/mV9GOuXx+g/+kPHyCikfwtYnmtNn+lbzTuQ
0a3sOHC4LATcVfZ3OSt+2Vdk5nHsLxGB2Xla1pI/4u/go3p2B3fFv6zAtPVsTyDh
qyg2qSji3w==
-----END CERTIFICATE-----''')


def test_ncp_w_legal_person_final_certificate():
    _assert_pem_is_certificate_type(CertificateType.NCP_W_LEGAL_PERSON_FINAL_CERTIFICATE, '''-----BEGIN CERTIFICATE-----
MIIHJzCCBQ+gAwIBAgIQVZHNRxiZp9LoR1nlajD1DDANBgkqhkiG9w0BAQsFADCB
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
OZiWGOTqNnxTAgMBAAGjggI1MIICMTAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwHwYDVR0jBBgwFoAUIpkkVwZsVnWO2+t9eWWcUzWp0ZEwIwYIKwYBBQUH
AQMEFzAVMBMGBgQAjkYBBjAJBgcEAI5GAQYDMIGXBggrBgEFBQcBAQSBijCBhzA4
BggrBgEFBQcwAYYsaHR0cDovL29jc3AuYXRoZXhncm91cC5nci9BdGhleFF1YWxp
ZmllZENBRzMwSwYIKwYBBQUHMAKGP2h0dHA6Ly9yZXBvLmF0aGV4Z3JvdXAuZ3Iv
QVRIRVhRdWFsaWZpZWRXRUJDZXJ0aWZpY2F0ZXNDQUczLmNydDAlBgNVHSAEHjAc
MA8GDSsGAQQBgeVaAQNkAQQwCQYHBACL7EABBjBPBgNVHR8ESDBGMESgQqBAhj5o
dHRwOi8vY3JsLmF0aGV4Z3JvdXAuZ3IvQVRIRVhRdWFsaWZpZWRXRUJDZXJ0aWZp
Y2F0ZXNDQUczLmNybDAdBgNVHQ4EFgQU07VGL6HuADDUGfAmLWYcVX4vqG0wDgYD
VR0PAQH/BAQDAgeAMHsGA1UdEQR0MHKCFHdlYmRzcy5hdGhleGdyb3VwLmdyghh3
ZWJkc3Ntb2NrLmF0aGV4Z3JvdXAuZ3KCGndlYmRzcy1ycHhyMS5pbmV0LmhlbGV4
Lmdygg9kc3MuYXRoZXhuZXQuZ3KCE2Rzc21vY2suYXRoZXhuZXQuZ3IwDAYDVR0T
AQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAmXiG4SmvTWDGoaEXOQJuFlhbjwG/
7MZCh18GeEhIfkOP0ClvalQImI8gbLo1DecfKDLLXLZpb7UTGtnpkKa2bDb+KyTy
r3Aprg9L+KnX4jM6KfrteZgDP63TcxGXnr3C3Mf5Y8vaFvlmazACRM/r830mnUj1
yvK8c7ZkIRhmt5a2C8lBoMFD+q15QqdU0vK4mV72EBi+xYRuAg7GVZoPM+dZhiNm
5dvKjAiaaOG58XKsnaeDDCDDWwjRJ7m8Y5ZaP6L8oGotvCmnXUjJcAmSE1MlXEjk
HsGkCqgwY6Wp/jDh4KpT8dQov1kg4dIKU9PNpdLjmmk/Jv7PMsG7i+3Q8lMCHfCe
6NxFnc3GZ62x6Gq6dKnIqDQzMvYUOnEPfVcfOaWmrmFAaBfVAXfRaXcgAPDknNPg
Ckdbi5ywuvbYckFOcVpv+1u+KqDYdxUMCSxSpls+o0J6c38FbcmuFfB7BYB8cTgu
cNAGUBur3ku6KO8fHcxpO3zLvA9I6LNhOmvLX24dPRprFd8uK+FiciNxbA3CjDGN
UtJUErRMG8RRUXYPAM0tF9fZpKm3SurevG01yO8m/AcmsMuKjzJ9LIle7ioZtDc7
C64ldoQ+IEA1QRyRo8qDml25rgvC3vTyQ4bngTunPPfEsSO04NT71G7va3DyV/VG
VbCnlkj7sIHIPRY=
-----END CERTIFICATE-----''')
