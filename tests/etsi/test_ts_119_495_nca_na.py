"""Unit tests for the TS 119 495 GEN-5.2.3-1A / GEN-5.2.3-5 "NA" rules.

These exercise NcaNaValueValidator and NCAIdValidator directly against a synthesised PSD2QcType, so that the
role-awareness of the "NA" exemption is pinned independently of the integration certificate fixtures.
"""

import pytest
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode

from pkilint import document, validation
from pkilint.etsi import ts_119_495
from pkilint.etsi.asn1 import ts_119_495 as ts_119_495_asn1


def _build_psd2_qc_type(role_oid, role_name, nca_name, nca_id):
    psd2_qc_type = ts_119_495_asn1.PSD2QcType()

    roles = ts_119_495_asn1.RolesOfPSP()
    role = ts_119_495_asn1.RoleOfPSP()
    role["roleOfPspOid"] = ts_119_495_asn1.RoleOfPspOid(str(role_oid))
    role["roleOfPspName"] = ts_119_495_asn1.RoleOfPspName(role_name)
    roles.setComponentByPosition(0, role)

    psd2_qc_type["rolesOfPSP"] = roles
    psd2_qc_type["nCAName"] = ts_119_495_asn1.NCAName(nca_name)
    psd2_qc_type["nCAId"] = ts_119_495_asn1.NCAId(nca_id)

    # round-trip through DER so the node tree mirrors what the decoder produces
    decoded, _ = decode(encode(psd2_qc_type), asn1Spec=ts_119_495_asn1.PSD2QcType())

    return document.PDUNode(None, "pSD2QcType", decoded, None)


def _codes(result):
    return {fd.finding.code for fd in result.finding_descriptions}


def _nca_na_codes(role_oid, role_name, nca_name, nca_id):
    node = _build_psd2_qc_type(role_oid, role_name, nca_name, nca_id)
    validator = ts_119_495.NcaNaValueValidator()

    return _codes(validator.validate(node))


def _nca_id_codes(role_oid, role_name, nca_name, nca_id):
    node = _build_psd2_qc_type(role_oid, role_name, nca_name, nca_id)
    validator = ts_119_495.NCAIdValidator()

    try:
        validator.validate(node.children["nCAId"])
    except validation.ValidationFindingEncountered as e:
        return {e.finding.code}

    return set()


_EXEMPT_ROLES = [
    (ts_119_495_asn1.id_psd2_role_psp_cb, "PSP_CB"),
    (ts_119_495_asn1.id_psd2_role_psp_pa, "PSP_PA"),
]

_NON_EXEMPT_ROLES = [
    (ts_119_495_asn1.id_psd2_role_psp_as, "PSP_AS"),
    (ts_119_495_asn1.id_psd2_role_psp_ai, "PSP_AI"),
    (ts_119_495_asn1.id_psd2_role_vop_rs, "VOP_RS"),
]


@pytest.mark.parametrize("role_oid,role_name", _EXEMPT_ROLES)
def test_exempt_role_with_na_is_permitted(role_oid, role_name):
    """GEN-5.2.3-1A and GEN-5.2.3-5: "NA" is the required value for PSP_CB and PSP_PA."""
    assert _nca_na_codes(role_oid, role_name, "NA", "NA") == set()
    assert _nca_id_codes(role_oid, role_name, "NA", "NA") == set()


@pytest.mark.parametrize("role_oid,role_name", _EXEMPT_ROLES)
def test_exempt_role_without_na_is_reported(role_oid, role_name):
    assert _nca_na_codes(role_oid, role_name, "National Bank of Belgium", "BE-NBB") == {
        "etsi.ts_119_495.gen-5.2.3-1a.nca_name_not_na",
        "etsi.ts_119_495.gen-5.2.3-5.nca_id_not_na",
    }


@pytest.mark.parametrize("role_oid,role_name", _NON_EXEMPT_ROLES)
def test_non_exempt_role_with_na_nca_name_is_reported(role_oid, role_name):
    """Regression: "NA" must not be accepted as an NCAName for a role other than PSP_CB/PSP_PA.

    NCANameLatinCharactersValidator cannot catch this, as "NA" is valid Latin text."""
    assert "etsi.ts_119_495.gen-5.2.3-1a.prohibited_nca_name_na_value" in _nca_na_codes(
        role_oid, role_name, "NA", "BE-NBB"
    )


@pytest.mark.parametrize("role_oid,role_name", _NON_EXEMPT_ROLES)
def test_non_exempt_role_with_na_nca_id_is_reported(role_oid, role_name):
    """Regression: the NCAIdValidator exemption for "NA" is role-aware, so for a non-exempt role "NA" is
    evaluated against the GEN-5.2.3-2 structure and reported."""
    assert _nca_id_codes(role_oid, role_name, "National Bank of Belgium", "NA") == {
        "etsi.ts_119_495.gen-5.2.3-2.invalid_structure"
    }


@pytest.mark.parametrize("role_oid,role_name", _NON_EXEMPT_ROLES)
def test_non_exempt_role_with_valid_values_is_clean(role_oid, role_name):
    assert (
        _nca_na_codes(role_oid, role_name, "National Bank of Belgium", "BE-NBB")
        == set()
    )
    assert (
        _nca_id_codes(role_oid, role_name, "National Bank of Belgium", "BE-NBB")
        == set()
    )
