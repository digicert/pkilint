import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pkilint import loader, validation
from pkilint.cabf import cabf_key, serverauth
from pkilint.pkix import certificate

_VALIDATOR_CLASS = cabf_key.EcdsaKeyValidator

_PRIVATE_KEY_TOO_SMALL = _VALIDATOR_CLASS.VALIDATION_PRIVATE_KEY_TOO_SMALL.code

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _create_certificate(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certs R Us CA")])
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(key, hashes.SHA384())
    )

    return loader.RFC5280CertificateDocumentLoader().load_pem_document(
        cert.public_bytes(serialization.Encoding.PEM).decode()
    )


def _lint(key):
    cert = _create_certificate(key)

    validator = certificate.create_pkix_certificate_validator_container(
        serverauth.create_decoding_validators(),
        [
            validation.ValidatorContainer(
                validators=[_VALIDATOR_CLASS()], path="certificate"
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


def test_private_key_4():
    """The smallest of the eMudhra intermediate keys."""
    assert _lint(ec.derive_private_key(4, ec.SECP384R1())) == {_PRIVATE_KEY_TOO_SMALL}


def test_private_key_237_near_limit():
    assert _lint(ec.derive_private_key(237, ec.SECP384R1())) == {_PRIVATE_KEY_TOO_SMALL}


def test_private_key_curve_order_minus_237():
    assert _lint(ec.derive_private_key(_P256_ORDER - 237, ec.SECP256R1())) == {
        _PRIVATE_KEY_TOO_SMALL
    }


def test_private_key_256_past_limit():
    assert _lint(ec.derive_private_key(256, ec.SECP256R1())) == set()


def test_random_private_key():
    assert _lint(ec.generate_private_key(ec.SECP384R1())) == set()
