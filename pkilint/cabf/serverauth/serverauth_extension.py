import datetime
from urllib.parse import urlparse

from pyasn1_alt_modules import rfc5280

from pkilint import validation, document


class CrlDpDistributionPointValidator(validation.Validator):
    """Validates that the fields included in the CRL distribution points extension conforms with BR 7.1.2.11.2."""

    VALIDATION_CRLDP_DP_PROHIBITED_FIELD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.crldp_dp_prohibited_field_present",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_CRLDP_DP_PROHIBITED_FIELD,
            pdu_class=rfc5280.DistributionPoint,
        )

    def validate(self, node):
        for prohibited_field in ("reasons", "cRLIssuer"):
            if prohibited_field in node.children:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_CRLDP_DP_PROHIBITED_FIELD,
                    f"Prohibited field present: {prohibited_field}",
                )


# BR 7.1.2.11.2
class CrlDpDistributionPointNameValidator(validation.Validator):
    """Validates that the names included in the CRL distribution points extension conforms with BR 7.1.2.11.2."""

    VALIDATION_PROHIBITED_FIELD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.crldp_dpname_prohibited_field_present",
    )

    VALIDATION_PROHIBITED_GENERALNAME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.crldp_dpname_prohibited_generalname_type",
    )

    VALIDATION_PROHIBITED_URI_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.crldp_dpname_prohibited_uri_scheme",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_PROHIBITED_FIELD,
                self.VALIDATION_PROHIBITED_GENERALNAME,
                self.VALIDATION_PROHIBITED_URI_SCHEME,
            ],
            pdu_class=rfc5280.DistributionPointName,
        )

    def validate(self, node):
        if "nameRelativeToCRLIssuer" in node.children:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_FIELD
            )

        gns = node.children["fullName"]

        prohibited_gn_types = {gn.child[0] for gn in gns.children.values()} - {
            "uniformResourceIdentifier"
        }

        if any(prohibited_gn_types):
            prohibited_types_str = ", ".join(prohibited_gn_types)

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_GENERALNAME,
                f"Prohibited GeneralName types present: {prohibited_types_str}",
            )

        for uri_node in (gn.child[1] for gn in gns.children.values()):
            scheme = urlparse(str(uri_node.pdu)).scheme

            if scheme.lower() != "http":
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_PROHIBITED_URI_SCHEME,
                    f'Prohibited URI scheme: "{scheme}"',
                )


class CrlDpDistributionPointCountValidator(validation.Validator):
    """Validates that the number of distribution points conforms with BR 7.1.2.11.2."""

    VALIDATION_MULTIPLE_CRLDP_DP = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.serverauth.crldp_multiple_distributionpoints_present",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_MULTIPLE_CRLDP_DP,
            pdu_class=rfc5280.CRLDistributionPoints,
        )

    def validate(self, node):
        if len(node.children) > 1:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_MULTIPLE_CRLDP_DP
            )


class AuthorityInformationAccessHttpUriLocationValidator(validation.Validator):
    """Validates that all locations in the AIA extension are HTTP as per BR 7.1.2.10.3, 7.1.2.7.7, and 7.1.2.8.3"""

    VALIDATION_AIA_LOCATION_NOT_URI = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.aia_location_not_uri",
    )

    VALIDATION_AIA_LOCATION_URI_NOT_HTTP = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.aia_location_uri_not_http",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_AIA_LOCATION_NOT_URI,
                self.VALIDATION_AIA_LOCATION_URI_NOT_HTTP,
            ],
            pdu_class=rfc5280.AccessDescription,
        )

    def validate(self, node):
        gn_type, value = node.children["accessLocation"].child

        if gn_type != "uniformResourceIdentifier":
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_AIA_LOCATION_NOT_URI,
                f"AIA access location is not URI: {gn_type}",
            )

        value_str = str(value.pdu)

        if not value_str.lower().startswith("http://"):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_AIA_LOCATION_URI_NOT_HTTP,
                f'AIA access location is not HTTP: "{value_str}"',
            )


# BR 7.1.2.10.3, 7.1.2.7.7, 7.1.2.8.3
class AuthorityInformationAccessUniqueLocationValidator(validation.Validator):
    """Validates that all URI locations in the AIA extension are unique, as per BR 7.1.2.10.3, 7.1.2.7.7,
    and 7.1.2.8.3."""

    VALIDATION_DUPLICATE_LOCATION_URI = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.aia_duplicate_location",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_DUPLICATE_LOCATION_URI,
            pdu_class=rfc5280.AuthorityInfoAccessSyntax,
        )

    def validate(self, node):
        uri_locations = []
        for access_description in node.children.values():
            location_type, location_value = access_description.children[
                "accessLocation"
            ].child

            if location_type == "uniformResourceIdentifier":
                uri_locations.append(str(location_value.pdu))

        duplicate_locations = {l for l in uri_locations if uri_locations.count(l) > 1}

        if any(duplicate_locations):
            dup_locations_str = ", ".join(sorted(list(duplicate_locations)))

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_DUPLICATE_LOCATION_URI,
                f'Duplicate AIA access locations: "{dup_locations_str}"',
            )


class CertificatePolicyQualifierValidator(validation.Validator):
    """Validates that the inclusion of policy qualifiers is in conformance with BR 7.1.2.3.2, 7.1.2.10.5,
    and 7.1.2.7.9."""

    VALIDATION_QUALIFIER_NOT_RECOMMENDED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.serverauth.certificate_policy_qualifier_present",
    )

    VALIDATION_PROHIBITED_QUALIFIER_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.prohibited_certificate_policy_qualifier_type",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_QUALIFIER_NOT_RECOMMENDED,
                self.VALIDATION_PROHIBITED_QUALIFIER_TYPE,
            ],
            pdu_class=rfc5280.PolicyQualifierInfo,
        )

    def validate(self, node):
        findings = [
            validation.ValidationFindingDescription(
                self.VALIDATION_QUALIFIER_NOT_RECOMMENDED, None
            )
        ]

        qualifier_type_oid = node.children["policyQualifierId"].pdu

        if qualifier_type_oid != rfc5280.id_qt_cps:
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_PROHIBITED_QUALIFIER_TYPE,
                    f"Prohibited qualifier type: {str(qualifier_type_oid)}",
                )
            )

        return validation.ValidationResult(self, node, findings)


class EvCpsUriPresenceValidator(validation.Validator):
    """Validates that EV Subscriber certificates contain the CPS URI qualifier, as per EVG 9.7."""

    VALIDATION_EV_CPS_URI_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.ev_guidelines.cps_uri_policy_qualifier_missing",
    )

    _VALIDATION_EV_CPS_URI_MISSING_INEFFECTIVE_DATE = datetime.datetime(
        2024, 5, 6, 0, 0, 0, tzinfo=datetime.timezone.utc
    )

    def __init__(
        self, validity_period_start_retriever: document.ValidityPeriodStartRetriever
    ):
        super().__init__(
            validations=self.VALIDATION_EV_CPS_URI_MISSING,
            pdu_class=rfc5280.CertificatePolicies,
        )

        self._validity_period_start_retriever = validity_period_start_retriever

    def match(self, node):
        return (
            super().match(node)
            and self._validity_period_start_retriever(node.document)
            < self._VALIDATION_EV_CPS_URI_MISSING_INEFFECTIVE_DATE
        )

    def validate(self, node):
        qualifier_oids = set()

        for pi in node.children.values():
            qualifiers = pi.children.get("policyQualifiers")

            if qualifiers is None:
                continue

            qualifier_oids.update(
                (
                    q.children["policyQualifierId"].pdu
                    for q in qualifiers.children.values()
                )
            )

        if rfc5280.id_qt_cps not in qualifier_oids:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_EV_CPS_URI_MISSING
            )
