from pyasn1_alt_modules import rfc5280, rfc6960, rfc6962, rfc4262

from pkilint import validation

EXTENSION_MAPPINGS = {
    **rfc4262._certificateExtensionsMap,
    **rfc6962._certificateExtensionsMapUpdate,
    **rfc6960._certificateExtensionsMapUpdate,
    **rfc5280.certificateExtensionsMap,
}


def get_criticality_from_decoded_node(node):
    ext_node = node.navigate("^.^")

    return bool(ext_node.children["critical"].pdu)


class PermittedExtensionValidator(validation.Validator):
    VALIDATION_CODE = "pkix.unknown_extension"

    def __init__(
        self, *, known_oids, severity=validation.ValidationFindingSeverity.ERROR
    ):
        self.known_oids = known_oids

        finding = [validation.ValidationFinding(severity, self.VALIDATION_CODE)]

        super().__init__(validations=finding, pdu_class=rfc5280.Extension)

    def validate(self, node):
        type_node = node.children["extnID"]
        oid = type_node.pdu

        if oid not in self.known_oids:
            raise validation.ValidationFindingEncountered(
                self.validations[0], f"Unknown extension type: {str(oid)}"
            )


class UniqueExtensionValidator(validation.Validator):
    VALIDATION_EXTENSION_NOT_UNIQUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.duplicate_extension"
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_EXTENSION_NOT_UNIQUE,
            pdu_class=rfc5280.Extensions,
        )

    def validate(self, node):
        oids = set()
        for child in node.children.values():
            oid = child.children["extnID"].pdu
            if oid in oids:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_EXTENSION_NOT_UNIQUE,
                    f'Multiple extensions of type "{str(oid)}"',
                )

            oids.add(oid)


class ExtensionCriticalityValidator(validation.Validator):
    def __init__(self, type_oid, is_critical, validation):
        self._type_oid = type_oid
        self._is_critical = is_critical
        self._validation = validation

        super().__init__(pdu_class=rfc5280.Extension, validations=[validation])

    def match(self, node):
        if not super().match(node):
            return False

        node_oid = node.children["extnID"].pdu

        return self._type_oid == node_oid

    def validate(self, node):
        criticality = bool(node.navigate("critical").pdu)

        if self._is_critical and not criticality:
            raise validation.ValidationFindingEncountered(
                self._validation, f"Extension {self._type_oid} is not critical"
            )
        elif not self._is_critical and criticality:
            raise validation.ValidationFindingEncountered(
                self._validation, f"Extension {self._type_oid} is critical"
            )


class ExtensionsDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(decode_func=decode_func, pdu_class=rfc5280.Extension, **kwargs)


class IssuerSubjectKeyIdentifierBinaryEqualValidator(validation.Validator):
    VALIDATION_AUTH_KEY_ID_EXTENSION_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.authority_key_id_extension_missing",
    )

    VALIDATION_AUTH_KEY_ID_KEYID_FIELD_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.authority_key_id_keyid_field_missing",
    )

    VALIDATION_KEY_IDENTIFIER_NOT_MATCH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.issuer_and_subject_key_identifier_not_equal",
    )

    def __init__(self, *, subject_auth_key_id_retriever):
        self._subject_auth_key_id_retriever = subject_auth_key_id_retriever

        super().__init__(
            validations=[
                self.VALIDATION_AUTH_KEY_ID_EXTENSION_MISSING,
                self.VALIDATION_AUTH_KEY_ID_KEYID_FIELD_MISSING,
                self.VALIDATION_KEY_IDENTIFIER_NOT_MATCH,
            ],
            pdu_class=rfc5280.SubjectKeyIdentifier,
        )

    def validate(self, node):
        auth_id_ext_and_idx = self._subject_auth_key_id_retriever(node)

        if auth_id_ext_and_idx is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_AUTH_KEY_ID_EXTENSION_MISSING
            )

        ext, _ = auth_id_ext_and_idx

        decoded_auth_key_id = ext.navigate("extnValue.authorityKeyIdentifier")

        key_id_node = decoded_auth_key_id.children.get("keyIdentifier")
        if key_id_node is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_AUTH_KEY_ID_KEYID_FIELD_MISSING
            )

        if bytes(key_id_node.pdu) != bytes(node.pdu):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_KEY_IDENTIFIER_NOT_MATCH
            )


class AuthorityKeyIdentifierCriticalityValidator(ExtensionCriticalityValidator):
    VALIDATION_CRITICAL_AKI = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.authority_key_identifier_critical",
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc5280.id_ce_authorityKeyIdentifier,
            is_critical=False,
            validation=self.VALIDATION_CRITICAL_AKI,
        )


class ExtensionPresenceValidator(validation.Validator):
    def __init__(self, *, extension_oid, validation, **kwargs):
        self._extension_oid = extension_oid
        self._validation = validation

        super().__init__(validations=[validation], **kwargs)

    def validate(self, node):
        ext_idx = node.document.get_extension_by_oid(self._extension_oid)

        if ext_idx is None:
            raise validation.ValidationFindingEncountered(self._validation)


class ExtensionTypeMatchingValidator(validation.TypeMatchingValidator):
    def __init__(self, *, extension_oid, validations):
        super().__init__(
            type_path="extnID",
            type_oid=extension_oid,
            value_path="extnValue",
            validations=validations,
            pdu_class=rfc5280.Extension,
        )


class AuthorityKeyIdentifierValidator(validation.Validator):
    VALIDATION_AKI_NO_KEY_ID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.authority_key_identifier_keyid_missing",
    )

    VALIDATION_AKI_NO_SERIAL_NUMBER = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.aki_with_cert_issuer_but_serial_number_absent",
    )

    VALIDATION_AKI_NO_CERT_ISSUER = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.aki_with_serial_number_but_cert_issuer_absent",
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.AuthorityKeyIdentifier,
            validations=[
                self.VALIDATION_AKI_NO_KEY_ID,
                self.VALIDATION_AKI_NO_CERT_ISSUER,
                self.VALIDATION_AKI_NO_SERIAL_NUMBER,
            ],
        )

    def validate(self, node):
        results = []

        if "keyIdentifier" not in node.children:
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_AKI_NO_KEY_ID, None
                )
            )

        if "authorityCertIssuer" in node.children and (
            "authorityCertSerialNumber" not in node.children
        ):
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_AKI_NO_SERIAL_NUMBER, None
                )
            )

        if "authorityCertSerialNumber" in node.children and (
            "authorityCertIssuer" not in node.children
        ):
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_AKI_NO_CERT_ISSUER, None
                )
            )

        return validation.ValidationResult(self, node, results)


class DistributionPointValidator(validation.Validator):
    VALIDATION_DP_NO_NAME_OR_ISSUER = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.distribution_point_does_not_contain_name_or_issuer",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_DP_NO_NAME_OR_ISSUER],
            pdu_class=rfc5280.DistributionPoint,
        )

    def validate(self, node):
        if (
            "distributionPoint" not in node.children
            and "cRLIssuer" not in node.children
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_DP_NO_NAME_OR_ISSUER
            )
