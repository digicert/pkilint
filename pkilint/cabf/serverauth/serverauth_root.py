import operator

from dateutil.relativedelta import relativedelta
from pyasn1_alt_modules import rfc5280, rfc6962

import pkilint.common
from pkilint import validation, document
from pkilint.pkix import time, Rfc2119Word


_CODE_CLASSIFIER = "cabf.serverauth.root"


class RootExtensionAllowanceValidator(
    pkilint.common.ExtensionIdentifierAllowanceValidator
):
    """Validates that the included extensions conform to BR 7.1.2.1.2."""

    _EXTENSION_ALLOWANCES = {
        rfc5280.id_ce_authorityKeyIdentifier: Rfc2119Word.SHOULD,
        rfc5280.id_ce_basicConstraints: Rfc2119Word.MUST,
        rfc5280.id_ce_keyUsage: Rfc2119Word.MUST,
        rfc5280.id_ce_subjectKeyIdentifier: Rfc2119Word.MUST,
        rfc5280.id_ce_extKeyUsage: Rfc2119Word.MUST_NOT,
        rfc5280.id_ce_certificatePolicies: Rfc2119Word.SHOULD_NOT,
        rfc6962.id_ce_embeddedSCT: Rfc2119Word.MAY,
    }

    def __init__(self):
        super().__init__(
            self._EXTENSION_ALLOWANCES, _CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT
        )


class RootSubjectIssuerIdenticalEncodingValidator(validation.DEREqualityValidator):
    """Validates that the encoding of the subject and issuer DN are identical, as per BR 7.1.2.1."""

    # BR 7.1.2.1
    VALIDATION_ROOT_SUBJECT_ISSUER_DN_ENCODING_NOT_IDENTICAL = (
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "cabf.serverauth.root_subject_issuer_name_encoding_not_equal",
        )
    )

    def __init__(self):
        super().__init__(
            other_node_retriever=lambda n: n.navigate("^.issuer"),
            validation=self.VALIDATION_ROOT_SUBJECT_ISSUER_DN_ENCODING_NOT_IDENTICAL,
            path="certificate.tbsCertificate.subject",
        )


class RootAkiSkiEqualityValidator(validation.Validator):
    """Validates that the key identifier as encoded in the subject key identifier and authority key identifier
    extensions is identical, as per BR 7.1.2.1.3."""

    VALIDATION_ROOT_SKI_AKI_NOT_EQUAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.root_aki_ski_not_equal",
    )

    @staticmethod
    def _get_aki_value_node(node):
        aki_and_idx = node.document.get_extension_by_oid(
            rfc5280.id_ce_authorityKeyIdentifier
        )

        if aki_and_idx is None:
            return None

        aki, _ = aki_and_idx

        try:
            return aki.navigate("extnValue.authorityKeyIdentifier.keyIdentifier")
        except document.PDUNavigationFailedError:
            return None

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_ROOT_SKI_AKI_NOT_EQUAL,
            pdu_class=rfc5280.SubjectKeyIdentifier,
        )

    def validate(self, node):
        aki_value_node = RootAkiSkiEqualityValidator._get_aki_value_node(node)

        if aki_value_node is None:
            return

        ski_octets = node.pdu.asOctets().hex()
        aki_octets = aki_value_node.pdu.asOctets().hex()

        if ski_octets != aki_octets:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ROOT_SKI_AKI_NOT_EQUAL,
                f'SKI octets: "{ski_octets}", AKI octets: "{aki_octets}"',
            )


class RootBasicConstraintsValidator(validation.Validator):
    """Validates that the content of the basic constraints extension conforms to BR 7.1.2.1.4."""

    VALIDATION_BC_CA_NOT_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.root_basic_constraints_ca_not_present",
    )

    VALIDATION_BC_PATHLEN_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.serverauth.root_basic_constraints_pathlenconstraint_present",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_BC_CA_NOT_PRESENT,
                self.VALIDATION_BC_PATHLEN_PRESENT,
            ],
            pdu_class=rfc5280.BasicConstraints,
        )

    def validate(self, node):
        if not bool(node.children["cA"].pdu):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_BC_CA_NOT_PRESENT
            )

        if "pathLenConstraint" in node.children:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_BC_PATHLEN_PRESENT
            )


class RootValidityPeriodValidator(time.ValidityPeriodThresholdsValidator):
    """Validates that the validity period conforms with BR 7.1.2.1.1."""

    VALIDATION_ROOT_VALIDITY_PERIOD_TOO_SHORT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.root_validity_period_too_short",
    )

    VALIDATION_ROOT_VALIDITY_PERIOD_TOO_LONG = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.root_validity_period_too_long",
    )

    def __init__(self):
        minimum_threshold = (
            operator.ge,
            relativedelta(days=2922),
            self.VALIDATION_ROOT_VALIDITY_PERIOD_TOO_SHORT,
        )
        maximum_threshold = (
            operator.le,
            relativedelta(days=9132),
            self.VALIDATION_ROOT_VALIDITY_PERIOD_TOO_LONG,
        )

        super().__init__(
            end_validity_node_retriever=lambda n: n.navigate("^.notAfter"),
            inclusive_second=True,
            validity_period_thresholds=[minimum_threshold, maximum_threshold],
            path="certificate.tbsCertificate.validity.notBefore",
        )
