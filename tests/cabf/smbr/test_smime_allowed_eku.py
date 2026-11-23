import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from pkilint import loader
from pkilint.cabf import smime
from pkilint.cabf.smime import smime_constants, smime_extension
from pkilint.pkix import certificate

_VALIDATOR_CLASS = smime_extension.AllowedExtendedKeyUsageValidator
_PROHIBITED_EKU_PRESENT = _VALIDATOR_CLASS.VALIDATION_PROHIBITED_EKU_PRESENT.code
_DOC_SIGNING_OID = ObjectIdentifier("1.3.6.1.4.1.311.10.3.12")

_KEY = ec.generate_private_key(ec.SECP256R1())


def _create_certificate(not_before: datetime.datetime, ekus):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=90))
        .add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
        .sign(_KEY, hashes.SHA256())
    )

    return loader.RFC5280CertificateDocumentLoader().load_pem_document(
        cert.public_bytes(serialization.Encoding.PEM).decode()
    )


def _lint(
    generation: smime_constants.Generation,
    not_before: datetime.datetime,
    ekus,
):
    cert = _create_certificate(not_before, ekus)

    validator = certificate.create_pkix_certificate_validator_container(
        smime.create_decoding_validators(),
        [
            smime.create_extensions_validator_container(
                smime_constants.ValidationLevel.MAILBOX,
                generation,
            )
        ],
    )

    results = validator.validate(cert.root)

    return {
        fd.finding.code
        for r in results
        for fd in r.finding_descriptions
        if r.validator.name == _VALIDATOR_CLASS.__name__
    }


def test_multipurpose_other_eku_allowed_before_sunset():
    before_sunset = datetime.datetime(
        2027, 6, 30, 23, 59, 59, tzinfo=datetime.timezone.utc
    )

    assert (
        _lint(
            smime_constants.Generation.MULTIPURPOSE,
            before_sunset,
            [ExtendedKeyUsageOID.EMAIL_PROTECTION, _DOC_SIGNING_OID],
        )
        == set()
    )


def test_multipurpose_client_auth_allowed_after_sunset():
    at_sunset = datetime.datetime(2027, 7, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    assert (
        _lint(
            smime_constants.Generation.MULTIPURPOSE,
            at_sunset,
            [
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ],
        )
        == set()
    )


def test_multipurpose_other_eku_prohibited_at_sunset():
    at_sunset = datetime.datetime(2027, 7, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    assert _lint(
        smime_constants.Generation.MULTIPURPOSE,
        at_sunset,
        [ExtendedKeyUsageOID.EMAIL_PROTECTION, _DOC_SIGNING_OID],
    ) == {_PROHIBITED_EKU_PRESENT}


def test_legacy_other_eku_prohibited_at_sunset():
    at_sunset = datetime.datetime(2027, 7, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

    assert _lint(
        smime_constants.Generation.LEGACY,
        at_sunset,
        [ExtendedKeyUsageOID.EMAIL_PROTECTION, _DOC_SIGNING_OID],
    ) == {_PROHIBITED_EKU_PRESENT}
