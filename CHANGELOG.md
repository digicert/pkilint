# Changelog

All notable changes to this project from version 0.9.3 onwards are documented in this file.

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
