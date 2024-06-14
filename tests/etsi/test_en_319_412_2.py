import pytest
from pyasn1_alt_modules import rfc5280

import pkilint.etsi.etsi_shared
from pkilint import document, validation
from pkilint.etsi import en_319_412_2


def _create_node(*bits):
    ku = rfc5280.KeyUsage(value=','.join(bits))

    return document.PDUNode(None, 'keyUsage', ku, None)


def test_setting_a():
    validator = en_319_412_2.NaturalPersonKeyUsageValidator(None)

    node = _create_node('nonRepudiation')

    assert validator.match(node)

    assert validator.validate(node) is None


def test_setting_d():
    validator = en_319_412_2.NaturalPersonKeyUsageValidator(None)

    node = _create_node('digitalSignature', 'keyEncipherment')

    assert validator.match(node)

    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)

    assert e.value.finding == pkilint.etsi.etsi_shared.KeyUsageValidator.VALIDATION_MIXED_KEY_USAGE_SETTING


def test_setting_a_prohibited():
    validator = en_319_412_2.NaturalPersonKeyUsageValidator(False)

    node = _create_node('nonRepudiation')

    assert validator.match(node)

    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)

    assert (
            e.value.finding ==
            en_319_412_2.NaturalPersonKeyUsageValidator.VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING
    )


def test_setting_c_prohibited():
    validator = en_319_412_2.NaturalPersonKeyUsageValidator(True)

    node = _create_node('digitalSignature')

    assert validator.match(node)

    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)

    assert (
            e.value.finding ==
            en_319_412_2.NaturalPersonKeyUsageValidator.VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING
    )


def test_non_preferred_content_commitment_setting():
    validator = en_319_412_2.NaturalPersonKeyUsageValidator(True)

    node = _create_node('digitalSignature', 'nonRepudiation')

    assert validator.match(node)

    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)

    assert (
            e.value.finding ==
            en_319_412_2.NaturalPersonKeyUsageValidator.VALIDATION_NON_PREFERRED_CONTENT_COMMITMENT_SETTING
    )


def test_mixed_use_setting():
    validator = en_319_412_2.NaturalPersonKeyUsageValidator(None)

    node = _create_node('digitalSignature', 'nonRepudiation')

    assert validator.match(node)

    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)

    assert e.value.finding == pkilint.etsi.etsi_shared.KeyUsageValidator.VALIDATION_MIXED_KEY_USAGE_SETTING


def test_invalid_extra_bit():
    validator = en_319_412_2.NaturalPersonKeyUsageValidator(None)

    node = _create_node('digitalSignature', 'cRLSign')

    assert validator.match(node)

    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)

    assert e.value.finding == pkilint.etsi.etsi_shared.KeyUsageValidator.VALIDATION_UNKNOWN_KEY_USAGE_SETTING


def test_invalid_both_bits():
    validator = en_319_412_2.NaturalPersonKeyUsageValidator(None)

    node = _create_node('digitalSignature', 'keyAgreement', 'keyEncipherment')

    assert validator.match(node)

    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)

    assert e.value.finding == pkilint.etsi.etsi_shared.KeyUsageValidator.VALIDATION_UNKNOWN_KEY_USAGE_SETTING
