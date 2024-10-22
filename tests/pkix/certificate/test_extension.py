import pytest
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280

from pkilint import document, validation
from pkilint.pkix.certificate import certificate_extension
from pkilint.pkix.certificate.certificate_extension import BasicConstraintsValidator
from pkilint.validation import ValidationFindingEncountered
from tests import util


def create_extension_with_value(oid, value_pdu, critical=False):
    ext_pdu = rfc5280.Extension()
    ext_pdu["extnID"] = oid
    ext_pdu["critical"] = critical

    value_der = encode(value_pdu)

    ext_pdu["extnValue"] = value_der

    ext = util.create_document(ext_pdu)

    name = document.get_node_name_for_pdu(value_pdu)

    value = document.PDUNode(ext.document, name, value_pdu, ext.children["extnValue"])

    ext.children["extnValue"].children[name] = value

    return value


def test_basic_constraints_notcritical_ca():
    bc_pdu = rfc5280.BasicConstraints()
    bc_pdu["cA"] = True

    bc = create_extension_with_value(rfc5280.id_ce_basicConstraints, bc_pdu)

    validator = BasicConstraintsValidator()

    assert validator.match(bc)

    with pytest.raises(ValidationFindingEncountered) as e:
        validator.validate(bc)

    assert e.value.finding == validator.VALIDATION_NOT_CRITICAL


def test_basic_constraints_not_ca_with_pathlen():
    bc_pdu = rfc5280.BasicConstraints()
    bc_pdu["cA"] = False
    bc_pdu["pathLenConstraint"] = 0

    bc = create_extension_with_value(rfc5280.id_ce_basicConstraints, bc_pdu)

    validator = BasicConstraintsValidator()

    assert validator.match(bc)

    with pytest.raises(ValidationFindingEncountered) as e:
        validator.validate(bc)

    assert e.value.finding == validator.VALIDATION_ILLEGAL_PATHLEN_SET


def _ee_extension_presence_test(ext_oid, validator, expected_finding):
    class Cert:
        @property
        def is_ca(self):
            return False

    ext = rfc5280.Extension()
    ext["extnID"] = ext_oid
    ext["extnValue"] = b""

    # noinspection PyTypeChecker
    node = document.PDUNode(Cert(), "ext", ext, None)

    assert validator.match(node)

    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(node)

    assert e.value.finding == expected_finding


def test_ee_policy_mappings_presence():
    _ee_extension_presence_test(
        rfc5280.id_ce_policyMappings,
        certificate_extension.PolicyMappingsPresenceValidator(),
        certificate_extension.PolicyMappingsPresenceValidator.VALIDATION_EE_POLICY_MAPPINGS_PRESENT,
    )


def test_ee_policy_constaints_presence():
    _ee_extension_presence_test(
        rfc5280.id_ce_policyConstraints,
        certificate_extension.PolicyConstraintsPresenceValidator(),
        certificate_extension.PolicyConstraintsPresenceValidator.VALIDATION_EE_POLICY_CONSTRAINTS_PRESENT,
    )


def test_ee_inhibit_anypolicy_presence():
    _ee_extension_presence_test(
        rfc5280.id_ce_inhibitAnyPolicy,
        certificate_extension.InhibitAnyPolicyPresenceValidator(),
        certificate_extension.InhibitAnyPolicyPresenceValidator.VALIDATION_EE_INHIBIT_ANYPOLICY_PRESENT,
    )


def test_issuer_alt_name_critical():
    gns = rfc5280.GeneralNames()

    gn = rfc5280.GeneralName()
    gn["dNSName"] = "foo.com"
    gns.append(gn)

    ext = rfc5280.Extension()
    ext["extnID"] = rfc5280.id_ce_issuerAltName
    ext["critical"] = True
    ext["extnValue"] = encode(gns)

    ext_node = document.PDUNode(None, "ext", ext, None)

    validator = certificate_extension.IssuerAlternativeNameCriticalityValidator()

    assert validator.match(ext_node)

    with pytest.raises(validation.ValidationFindingEncountered) as e:
        validator.validate(ext_node)

    assert (
        e.value.finding
        == certificate_extension.IssuerAlternativeNameCriticalityValidator.VALIDATION_ISSUER_ALT_NAME_CRITICAL
    )
