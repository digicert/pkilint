from pyasn1_alt_modules import rfc5280

from pkilint import validation, document
from pkilint.pkix import certificate, general_name


class EndEntityRevocationInformationPresenceValidator(validation.Validator):
    """
    Microsoft Root Program Requirements, 3.A.5:

    An end-entity certificate may contain either an AIA extension with a valid OCSP URL and/or a CDP extension pointing
    to a valid HTTP endpoint containing the CRL.
    """

    VALIDATION_REVOCATION_INFORMATION_ABSENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "msft.end_entity.revocation_information_absent",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_REVOCATION_INFORMATION_ABSENT],
            pdu_class=rfc5280.Extensions,
        )

    @classmethod
    def _general_name_is_http_uri(cls, gn):
        gn_type, gn_value = gn.child

        return (
            gn_type == general_name.GeneralNameTypeName.UNIFORM_RESOURCE_IDENTIFIER
            and str(gn_value.pdu).lower().startswith("http://")
        )

    @classmethod
    def _has_ocsp_http_uri(cls, cert: certificate.RFC5280Certificate):
        aia_ext_and_idx = cert.get_extension_by_oid(rfc5280.id_pe_authorityInfoAccess)

        if aia_ext_and_idx is None:
            return False

        aia_ext, _ = aia_ext_and_idx

        # ensure that the decoded value is present
        try:
            aia_ext_value = aia_ext.navigate("extnValue.authorityInfoAccessSyntax")
        except document.PDUNavigationFailedError:
            return False

        ocsp_gns = (
            ad.children["accessLocation"]
            for ad in aia_ext_value.children.values()
            if ad.children["accessMethod"].pdu == rfc5280.id_ad_ocsp
        )

        return any(cls._general_name_is_http_uri(gn) for gn in ocsp_gns)

    @classmethod
    def _has_crldp_http_uri(cls, cert: certificate.RFC5280Certificate):
        crldp_ext_and_idx = cert.get_extension_by_oid(
            rfc5280.id_ce_cRLDistributionPoints
        )

        if crldp_ext_and_idx is None:
            return False

        crldp_ext, _ = crldp_ext_and_idx

        # ensure that the decoded value is present
        try:
            crldp_ext_value = crldp_ext.navigate("extnValue.cRLDistributionPoints")
        except document.PDUNavigationFailedError:
            return False

        for dp in crldp_ext_value.children.values():
            dpn = dp.children.get("distributionPoint")

            if dpn is None:
                continue

            full_name = dpn.children.get("fullName")

            if full_name is None:
                continue

            if any(
                cls._general_name_is_http_uri(gn) for gn in full_name.children.values()
            ):
                return True

        return False

    def validate(self, node):
        cert_doc = node.document

        has_aia_ocsp_http_uri = self._has_ocsp_http_uri(cert_doc)
        has_crldp_http_uri = self._has_crldp_http_uri(cert_doc)

        if not has_aia_ocsp_http_uri and not has_crldp_http_uri:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_REVOCATION_INFORMATION_ABSENT
            )
