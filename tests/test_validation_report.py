from pkilint import validation, etsi
from pkilint.etsi import etsi_constants
from pkilint.pkix import certificate
from pkilint.cabf import serverauth, smime


def _test(validator, context: str):
    declared_validations = {getattr(validator, a) for a in dir(validator) if a.startswith('VALIDATION_')}

    reported_validations = set(validator.validations)

    missing_validations = declared_validations - reported_validations

    assert not any(missing_validations), (
        f'{context}: {validator.__class__.__name__} does not declare that it reports the following finding(s): '
        f'{missing_validations}'
    )

    if isinstance(validator, validation.ValidatorContainer):
        for v in validator.validators:
            _test(v, context)


def test_serverauth():
    for cert_type in serverauth.serverauth_constants.CertificateType:
        validator = certificate.create_pkix_certificate_validator_container(
            serverauth.create_decoding_validators(),
            serverauth.create_validators(cert_type)
        )

        context = f'cabf.serverauth.{cert_type}'

        _test(validator, context)


def test_smime():
    for validation_level in smime.smime_constants.ValidationLevel:
        for generation in smime.smime_constants.Generation:
            validator = certificate.create_pkix_certificate_validator_container(
                smime.create_decoding_validators(),
                smime.create_subscriber_validators(validation_level, generation)
            )

            context = f'cabf.smime.{validation_level}-{generation}'

            _test(validator, context)


def test_etsi():
    for certificate_type in etsi_constants.CertificateType:
        validator = certificate.create_pkix_certificate_validator_container(
            serverauth.create_decoding_validators(),
            etsi.create_validators(certificate_type)
        )

        context = f'etsi.{certificate_type}'

        _test(validator, context)
