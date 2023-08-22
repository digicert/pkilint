import pytest
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280

from pkilint import document
from pkilint.pkix.certificate.certificate_extension import BasicConstraintsValidator
from pkilint.validation import ValidationFindingEncountered
from tests import util


def create_extension_with_value(oid, value_pdu, critical=False):
    ext_pdu = rfc5280.Extension()
    ext_pdu['extnID'] = oid
    ext_pdu['critical'] = critical

    value_der = encode(value_pdu)

    ext_pdu['extnValue'] = value_der

    ext = util.create_document(ext_pdu)

    name = document.get_node_name_for_pdu(value_pdu)

    value = document.PDUNode(ext.document, name, value_pdu,
                             ext.children['extnValue']
                             )

    ext.children['extnValue'].children[name] = value

    return value


def test_basic_constraints_notcritical_ca():
    bc_pdu = rfc5280.BasicConstraints()
    bc_pdu['cA'] = True

    bc = create_extension_with_value(rfc5280.id_ce_basicConstraints, bc_pdu)

    validator = BasicConstraintsValidator()

    assert validator.match(bc)

    with pytest.raises(ValidationFindingEncountered) as e:
        validator.validate(bc)

    assert e.value.finding == validator.VALIDATION_NOT_CRITICAL


def test_basic_constraints_not_ca_with_pathlen():
    bc_pdu = rfc5280.BasicConstraints()
    bc_pdu['cA'] = False
    bc_pdu['pathLenConstraint'] = 0

    bc = create_extension_with_value(rfc5280.id_ce_basicConstraints, bc_pdu)

    validator = BasicConstraintsValidator()

    assert validator.match(bc)

    with pytest.raises(ValidationFindingEncountered) as e:
        validator.validate(bc)

    assert e.value.finding == validator.VALIDATION_ILLEGAL_PATHLEN_SET
