# Changelog

All notable changes to this project from version 0.9.3 onwards are documented in this file.

## 0.12.6 - 2025-01-13

### New features/enhancements

- Support for ML-DSA, SLH-DSA, and ML-KEM algorithms (#145)

### Fixes

- Gracefully handle SAN decoding errors when subject emailAddress attribute is present (#143)

## 0.12.5 - 2024-11-27

### Fixes

- Fix S/MIME BR version number (#142)

## 0.12.4 - 2024-11-25

### New features/enhancements

- Add support for short-lived TLS BR certificates (#133)
- Add support for TLS BR ballot SC-79 (#127)
- Add support for S/MIME BR ballot SMC-09 (#128)
- Add public key algorithm and key usage value consistency validation (#139)

### Fixes

- Gracefully handle unsupported public key algorithms (#134)
- Gracefully handle unsupported signature algorithms (#140 - found by @jon-oracle)

## 0.12.3 - 2024-10-23

### New features/enhancements

- Reformat codebase to use [Black](https://github.com/psf/black) (#125)

## 0.12.2 - 2024-10-14

### Fixes

- Fix typo in finding code for multiple TLS BR policy OIDs in Subscriber certificates (#122 - found by @robstradling)

## 0.12.1 - 2024-10-14

### New features/enhancements

- Add REST API endpoint for linting certificates with the PKIX linter (#119)
- Add support for Python 3.13 (#120)

## 0.12.0 - 2024-10-02

### New features/enhancements

- Add REST API for linting CRLs (#113 - implemented by @dipaktilekar)
- Add validator to flag HTML entities in subject attribute values (#116)
- Add --document-format CLI flag (#115)

### Fixes

- Remove duplicate registration of GeneralNameIpAddressSyntaxValidator in CRL linter (#103 - found by @zzzsz)
- Amend finding code for CRL reason code validator (#104 - found by @zzzsz)
- Remove duplicate registration of CRL validity period validator, fix positive validity period validator (#106 - found by @zzzsz)

## 0.11.4 - 2024-08-29

### New features/enhancements

- Use pyasn1-fasder for ASN.1 DER decoding by default (#98)
- Add support for S/MIME working group ballot SMC-08 (#101)

## 0.11.3 - 2024-07-17

### Fixes

- NCP-w legal person and natural person final certificates are incorrectly detected as pre-certificates (#92 - fixed by @robstradling)

## 0.11.2 - 2024-07-16

### Fixes

- Gracefully handle mis-encoded extensions and fields exposed as properties (#88)

## 0.11.1 - 2024-07-02

### New features/enhancements

- Add support for PEM-encoded OCSP responses (#86)
- Add validator to verify that the PSD2 policy OID is only asserted in PSD2 certificates (#87)
- Add validator to flag insignificant attribute values (#84)

### Fixes

- Perform case-sensitive match for ISO 3166-1 country codes (#83)

## 0.11.0 - 2024-06-14

### New features/enhancements

- Add support for linting ETSI website authentication certificates (#80)
- Add opt-in support for using [pyasn1-fasder](https://github.com/CBonnell/pyasn1-fasder) to decode DER (#81)

## 0.10.3 - 2024-05-13

### New features/enhancements

- Add support for SMIME BR ballot SMC-06 (#74)

### Fixes

- Flag invalid domain name length in GeneralName types (#78)

## 0.10.2 - 2024-05-07

### New features/enhancements

- Add support for TLS BR ballot SC-72 (#73). The effective date of this change is 2024-05-06.

## 0.10.1 - 2024-04-22

### Fixes

- Clamp CLI exit codes (#76)

## 0.10.0 - 2024-04-11

### New features/enhancements

- Add REST API endpoints for linting OCSP responses (#62 - implemented by @mans-andersson)

### Fixes

- Handle malformed inputs given via the CLI more gracefully (#63 - fixed by @ralienpp)
- Pin validators package version to work around issue in latest version (#65)

## 0.9.10 - 2024-03-04

### New features/enhancements

- SC-68: Allow EL and XI as the country code for VAT registration scheme (#60)

## 0.9.9 - 2023-12-18

### Fixes

- SaneValidityPeriodValidator incorrectly reports "pkix.invalid_time_syntax" for negative validity periods (#57)
- Decoder mapping for QcCompliance and QcSSCD statements incorrectly mapped to None (#58)

### New features/enhancements

- Add detection of SKI calculation methods described in RFC 7093 to SubjectKeyIdentifierValidator (#56)

## 0.9.8 - 2023-11-21

### Fixes

- HTTP 422 errors from REST API do not return a list of ValidationErrors in some cases (#54)

## 0.9.7 - 2023-11-03

### Fixes

- cabf.smime.common_name_value_unknown_source finding is incorrectly reported when SmtpUtf8Mailbox SAN values appear in the subject CN (#52 - reported and fixed by @hablutzel1)

## 0.9.6 - 2023-10-25

### Fixes

- PrintableStringConstraintValidator should flag invalid characters in tagged PrintableStrings (#48)

### New features/enhancements

- Bump Docker image to Python 3.12 (#50)

## 0.9.5 - 2023-09-29

### Fixes

- Stopping Docker container when executing external command results in immediate shutdown of container (#45)

## 0.9.4 - 2023-09-28

### New features/enhancements

- Publish Docker images (#43)

## 0.9.3 - 2023-09-20

### New features/enhancements

- Explicitly support Python 3.12 (#34)
- Add REST endpoint that returns the set of possible findings for a specific linter (#36)
- Surround document-sourced string values with double quotes in finding messages (#41)

### Fixes

- Suppress `ValueError` stack trace when `lint_cabf_smime_cert` can't determine certificate type (#37)
- `OrganizationIdentifierCountryNameConsistentValidator` should perform a case-insensitive country comparison (#38)
- Change severity of `cabf.smime.email_address_in_attribute_not_in_san` from WARNING to ERROR (#39)
- Decoding error when determining certificate type returns HTTP 500 (#40)
