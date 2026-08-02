import datetime
import pytest
from pyasn1_alt_modules import rfc3279
from pkilint import document, validation
from pkilint.etsi import ts_119_312


class _StubCertificate:
    """A minimal stand-in for pkilint.pkix.certificate.RFC5280Certificate that exposes only the
    attributes required by RsaKeySunsetValidator."""

    def __init__(self, not_before, not_after):
        self.not_before = not_before
        self.not_after = not_after


def _create_node(modulus_bit_length, not_before, not_after, exponent=65537):
    # sets the top bit so that the modulus has precisely the specified bit length
    modulus = 1 << (modulus_bit_length - 1)
    rsa_public_key = rfc3279.RSAPublicKey()
    rsa_public_key["modulus"] = modulus
    rsa_public_key["publicExponent"] = exponent
    stub_cert = _StubCertificate(not_before, not_after)
    return document.PDUNode(stub_cert, "rSAPublicKey", rsa_public_key, None)


# the last instant at which issuance is still considered "on or before 2026-12-31"
_BEFORE_SUNSET = datetime.datetime(
    2026, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc
)
# the first instant which is considered "after 2026-12-31"
_AT_SUNSET = datetime.datetime(2027, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
# the last instant which is still considered "no later than 2028-12-31"
_BEFORE_MAX_VALIDITY_END = datetime.datetime(
    2028, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc
)
# the first instant which is no longer considered "no later than 2028-12-31"
_AT_MAX_VALIDITY_END = datetime.datetime(
    2029, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
)


def test_large_key_is_always_permitted():
    validator = ts_119_312.RsaKeySunsetValidator()
    node = _create_node(3000, _AT_SUNSET, _AT_MAX_VALIDITY_END)
    assert validator.match(node)
    assert validator.validate(node) is None


def test_legacy_key_compliant_with_sunset_and_end_date_is_permitted():
    validator = ts_119_312.RsaKeySunsetValidator()
    node = _create_node(2048, _BEFORE_SUNSET, _BEFORE_MAX_VALIDITY_END)
    assert validator.validate(node) is None


def test_legacy_key_issued_after_sunset_date_is_prohibited():
    validator = ts_119_312.RsaKeySunsetValidator()
    node = _create_node(2048, _AT_SUNSET, _BEFORE_MAX_VALIDITY_END)
    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)
    assert (
        e.value.finding
        == validator.VALIDATION_RSA_KEY_SIZE_PROHIBITED_AFTER_SUNSET_DATE
    )


def test_small_key_issued_after_sunset_date_is_prohibited():
    validator = ts_119_312.RsaKeySunsetValidator()
    # a modulus below the 1 900-bit "legacy" band is also prohibited after the sunset date, per the broader
    # "only RSA keys with a length of at least 3 000 bits ... shall be used" requirement
    node = _create_node(1024, _AT_SUNSET, _BEFORE_MAX_VALIDITY_END)
    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)
    assert (
        e.value.finding
        == validator.VALIDATION_RSA_KEY_SIZE_PROHIBITED_AFTER_SUNSET_DATE
    )


def test_modulus_length_boundary_2999_bits_is_subject_to_sunset_date():
    validator = ts_119_312.RsaKeySunsetValidator()
    node = _create_node(2999, _AT_SUNSET, _BEFORE_MAX_VALIDITY_END)
    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)
    assert (
        e.value.finding
        == validator.VALIDATION_RSA_KEY_SIZE_PROHIBITED_AFTER_SUNSET_DATE
    )


def test_legacy_key_validity_period_exceeds_end_date_is_prohibited():
    validator = ts_119_312.RsaKeySunsetValidator()
    node = _create_node(2048, _BEFORE_SUNSET, _AT_MAX_VALIDITY_END)
    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)
    assert (
        e.value.finding
        == validator.VALIDATION_RSA_LEGACY_KEY_VALIDITY_PERIOD_EXCEEDS_END_DATE
    )


def test_modulus_length_boundary_1900_bits_is_subject_to_end_date_cap():
    validator = ts_119_312.RsaKeySunsetValidator()
    node = _create_node(1900, _BEFORE_SUNSET, _AT_MAX_VALIDITY_END)
    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)
    assert (
        e.value.finding
        == validator.VALIDATION_RSA_LEGACY_KEY_VALIDITY_PERIOD_EXCEEDS_END_DATE
    )


def test_small_key_issued_before_sunset_date_is_not_subject_to_end_date_cap():
    validator = ts_119_312.RsaKeySunsetValidator()
    # the validity period end date cap is scoped to keys within the 1 900-2 999 bit "legacy" band; smaller keys
    # are out of scope for this specific validator (a separate, pre-existing validator flags small moduli generally)
    node = _create_node(1899, _BEFORE_SUNSET, _AT_MAX_VALIDITY_END)
    assert validator.validate(node) is None
