from urllib.parse import urlparse

from pyasn1_alt_modules import rfc5280

from pkilint import validation, common
from pkilint.pkix import extension


class AuthorityInformationAccessPresenceValidator(extension.ExtensionPresenceValidator):
    _VALIDATION_TYPE = "cabf.aia_extension_missing"

    def __init__(self, severity):
        finding = validation.ValidationFinding(severity, self._VALIDATION_TYPE)

        super().__init__(
            extension_oid=rfc5280.id_pe_authorityInfoAccess,
            validation=finding,
            pdu_class=rfc5280.Extensions,
        )


def _general_name_is_http_uri(node):
    name, value = node.child

    return name == "uniformResourceIdentifier" and str(value.pdu).lower().startswith(
        "http:"
    )


def _validate_descriptions(node, access_method, empty_finding, no_http_finding):
    ads = [
        ad
        for ad in node.children.values()
        if ad.children["accessMethod"].pdu == access_method
    ]

    if len(ads) == 0:
        if empty_finding is None:
            return
        else:
            raise validation.ValidationFindingEncountered(empty_finding)

    if not any(
        filter(lambda a: _general_name_is_http_uri(a.children["accessLocation"]), ads)
    ):
        raise validation.ValidationFindingEncountered(no_http_finding)


class AuthorityInformationAccessContainsHttpUriValidator(validation.Validator):
    VALIDATION_NO_CA_ISSUERS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING, "cabf.aia_ca_issuers_missing"
    )

    VALIDATION_CA_ISSUERS_NO_HTTP_URI = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.aia_ca_issuers_has_no_http_uri",
    )

    VALIDATION_OCSP_NO_HTTP_URI = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.aia_ocsp_has_no_http_uri"
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_NO_CA_ISSUERS,
                self.VALIDATION_CA_ISSUERS_NO_HTTP_URI,
                self.VALIDATION_OCSP_NO_HTTP_URI,
            ],
            pdu_class=rfc5280.AuthorityInfoAccessSyntax,
        )

    def validate(self, node):
        _validate_descriptions(
            node,
            rfc5280.id_ad_caIssuers,
            self.VALIDATION_NO_CA_ISSUERS,
            self.VALIDATION_CA_ISSUERS_NO_HTTP_URI,
        )
        _validate_descriptions(
            node, rfc5280.id_ad_ocsp, None, self.VALIDATION_OCSP_NO_HTTP_URI
        )


class CrlDpContainsHttpUriValidator(validation.Validator):
    VALIDATION_CRLDP_NO_HTTP_URI = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.no_http_crldp_uri"
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_CRLDP_NO_HTTP_URI],
            pdu_class=rfc5280.CRLDistributionPoints,
        )

    def validate(self, node):
        for dist_point in node.children.values():
            dp = dist_point.children.get("distributionPoint")

            if dp is None:
                continue

            full_name = dp.children.get("fullName")
            if full_name is None:
                continue

            for gn in full_name.children.values():
                name, value = gn.child
                if name == "uniformResourceIdentifier" and str(
                    value.pdu
                ).lower().startswith("http:"):
                    return

        raise validation.ValidationFindingEncountered(self.VALIDATION_CRLDP_NO_HTTP_URI)


class CertificatePoliciesCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_CERTIFICATE_POLICIES_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.critical_certificate_policies_extension",
    )

    def __init__(self):
        super().__init__(
            validation=self.VALIDATION_CERTIFICATE_POLICIES_CRITICAL,
            type_oid=rfc5280.id_ce_certificatePolicies,
            is_critical=False,
        )


class CabfCrlDpCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_CRLDP_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.critical_crldp_extension"
    )

    def __init__(self):
        super().__init__(
            validation=self.VALIDATION_CRLDP_CRITICAL,
            type_oid=rfc5280.id_ce_cRLDistributionPoints,
            is_critical=False,
        )


class CabfAuthorityKeyIdentifierValidator(validation.Validator):
    VALIDATION_AKI_HAS_ISSUER_CERT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.authority_key_identifier_has_issuer_cert",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_AKI_HAS_ISSUER_CERT],
            pdu_class=rfc5280.AuthorityKeyIdentifier,
        )

    def validate(self, node):
        if (
            "authorityCertIssuer" in node.children
            or "authorityCertSerialNumber" in node.children
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_AKI_HAS_ISSUER_CERT
            )


class CabfExtensionsPresenceValidator(common.ExtensionsPresenceValidator):
    VALIDATION_EXTENSIONS_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.certificate_extensions_missing",
    )

    def __init__(self):
        super().__init__(self.VALIDATION_EXTENSIONS_MISSING)


class CpsUriHttpValidator(validation.Validator):
    VALIDATION_CPS_URI_NOT_HTTP = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.cps_uri_is_not_http"
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_CPS_URI_NOT_HTTP], pdu_class=rfc5280.CPSuri
        )

    def validate(self, node):
        uri = str(node.pdu)
        scheme = urlparse(uri).scheme

        if scheme.lower() not in {"http", "https"}:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CPS_URI_NOT_HTTP, f'Prohibited URI scheme: "{scheme}"'
            )
