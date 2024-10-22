import collections
from typing import List, Set

import validators
from pyasn1.type.univ import ObjectIdentifier
from pyasn1_alt_modules import rfc5280, rfc2985

from pkilint import document, validation, oid
from pkilint.itu import x520_name

ATTRIBUTE_TYPE_MAPPINGS = {
    **x520_name.ATTRIBUTE_TYPE_MAPPINGS,
    **rfc2985._certificateAttributesMapUpdate,
    **rfc5280.certificateAttributesMap,
}


def get_name_attributes_by_type(name_node, type_oid):
    atvs = []

    for rdn_idx, rdn in name_node.children["rdnSequence"].children.items():
        for atv_idx, atv in rdn.children.items():
            if atv.children["type"].pdu == type_oid:
                atvs.append((atv, (int(rdn_idx), int(atv_idx))))

    return atvs


def get_name_attribute_counts(name_node):
    counts = collections.Counter()

    for rdn_idx, rdn in name_node.children["rdnSequence"].children.items():
        counts.update((atv.children["type"].pdu for atv in rdn.children.values()))

    return counts


class EmptyNameValidator(validation.Validator):
    VALIDATION_NAME_IS_EMPTY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.name_empty"
    )

    def __init__(self, **kwargs):
        super().__init__(
            validations=[self.VALIDATION_NAME_IS_EMPTY],
            pdu_class=rfc5280.RDNSequence,
            **kwargs,
        )

    def validate(self, node):
        if len(node.children) == 0:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NAME_IS_EMPTY,
            )


class RDNContainsUniqueTypesValidator(validation.Validator):
    VALIDATION_ATTRIBUTE_TYPES_NOT_UNIQUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.rdn_contains_duplicate_attribute_types",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_ATTRIBUTE_TYPES_NOT_UNIQUE,
            pdu_class=rfc5280.RelativeDistinguishedName,
        )

    def validate(self, node):
        oids = set()
        for child in node.children.values():
            oid = child.children["type"].pdu
            if oid in oids:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_ATTRIBUTE_TYPES_NOT_UNIQUE,
                    f'Multiple attributes of type "{str(oid)}"',
                )

            oids.add(oid)


class NameAttributeTypesValidatorBase(validation.Validator):
    def __init__(
        self,
        *,
        expected_oid_set: Set[ObjectIdentifier],
        validation: validation.ValidationFinding,
        **kwargs,
    ):
        self.expected_oid_set = expected_oid_set
        self.validation = validation

        super().__init__(
            validations=[self.validation], pdu_class=rfc5280.RDNSequence, **kwargs
        )

    def validate_attributes(
        self, node: document.PDUNode, attributes: List[ObjectIdentifier]
    ) -> validation.ValidationResult:
        pass

    def validate(self, node):
        attributes = []

        for rdn in node.children.values():
            attributes += [atv.children["type"].pdu for atv in rdn.children.values()]

        return self.validate_attributes(node, attributes)


class PermittedAttributeTypeValidator(NameAttributeTypesValidatorBase):
    def __init__(self, *, allowed_oid_set, validation):
        super().__init__(expected_oid_set=allowed_oid_set, validation=validation)

    def validate_attributes(self, node, attributes):
        attributes = set(attributes)

        prohibited_oids = attributes - self.expected_oid_set

        if len(prohibited_oids) > 0:
            oids_str = oid.format_oids(prohibited_oids)

            raise validation.ValidationFindingEncountered(
                self.validation, f"Prohibited attribute types: {oids_str}"
            )


class RequiredAttributeTypeValidator(NameAttributeTypesValidatorBase):
    def __init__(self, *, required_oid_set, validation):
        super().__init__(expected_oid_set=required_oid_set, validation=validation)

    def validate_attributes(self, node, attributes):
        attributes = set(attributes)

        missing_oids = self.expected_oid_set - attributes

        if len(missing_oids) > 0:
            oids_str = oid.format_oids(missing_oids)

            raise validation.ValidationFindingEncountered(
                self.validation, f"Required attribute types not present: {oids_str}"
            )


class NameDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(
            decode_func=decode_func, pdu_class=rfc5280.AttributeTypeAndValue, **kwargs
        )


class IssuerSubjectNameBinaryEqualValidator(validation.DEREqualityValidator):
    VALIDATION_ISSUER_AND_SUBJECT_NOT_DER_EQUAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "pkix.issuer_and_subject_dn_not_binary_equal",
    )

    def _retrieve_subject_issuer_dn(self, node):
        return node.navigate(self._subject_document_issuer_dn_path)

    def __init__(self, *, subject_document_issuer_dn_path, **kwargs):
        self._subject_document_issuer_dn_path = subject_document_issuer_dn_path

        super().__init__(
            other_node_retriever=self._retrieve_subject_issuer_dn,
            validation=self.VALIDATION_ISSUER_AND_SUBJECT_NOT_DER_EQUAL,
            **kwargs,
        )


class DomainComponentValidDomainNameValidator(validation.Validator):
    VALIDATION_NAME_DC_NOT_A_VALID_DOMAIN_NAME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.name_domain_components_invalid_domain_name",
    )

    def __init__(self, **kwargs):
        super().__init__(
            validations=[self.VALIDATION_NAME_DC_NOT_A_VALID_DOMAIN_NAME], **kwargs
        )

    def validate(self, node):
        atvs = node.document.get_name_attributes_by_type(
            rfc5280.id_domainComponent, f":{node.path}"
        )

        try:
            components = [str(a.navigate("value.domainComponent").pdu) for a, _ in atvs]
        except document.PDUNavigationFailedError:
            return

        components.reverse()

        domain_name = ".".join(components)

        if len(domain_name) > 0:
            ret = validators.domain(domain_name)

            if not isinstance(ret, bool) or not ret:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_NAME_DC_NOT_A_VALID_DOMAIN_NAME,
                    f'Invalid domain name in domainComponents: "{domain_name}"',
                )


class DuplicateAttributeTypeValidator(NameAttributeTypesValidatorBase):
    def __init__(self, *, allowed_duplicate_oid_set, validation):
        super().__init__(
            expected_oid_set=allowed_duplicate_oid_set,
            validation=validation,
        )

    def validate_attributes(self, node, attributes):
        duplicates = set((o for o in attributes if attributes.count(o) > 1))

        disallowed_duplicates = duplicates - self.expected_oid_set

        if len(disallowed_duplicates) > 0:
            oids_str = oid.format_oids(disallowed_duplicates)

            raise validation.ValidationFindingEncountered(
                self.validation,
                f"Prohibited multiple instances of attribute types: {oids_str}",
            )
