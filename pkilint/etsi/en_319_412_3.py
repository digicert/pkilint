from pyasn1_alt_modules import rfc5280

from pkilint import common
from pkilint import validation
from pkilint.itu import x520_name
from pkilint.pkix import Rfc2119Word, name

_REQUIRED_ATTRIBUTES = {
    rfc5280.id_at_countryName,
    rfc5280.id_at_organizationName,
    x520_name.id_at_organizationIdentifier,
    rfc5280.id_at_commonName,
}


class LegalPersonSubjectAttributeAllowanceValidator(common.AttributeIdentifierAllowanceValidator):
    """
    LEG-4.2.1-2: The subject field shall include at least the following attributes as specified in Recommendation
    ITU-T X.520
    """
    _CODE_CLASSIFIER = 'etsi.en_319_412_3.leg-4.2.1-2'

    _ATTRIBUTE_ALLOWANCES = {a: Rfc2119Word.MUST for a in _REQUIRED_ATTRIBUTES}

    def __init__(self):
        super().__init__(self._ATTRIBUTE_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.MAY)


class LegalPersonDuplicateAttributeAllowanceValidator(validation.Validator):
    """
    LEG-4.2.1-3: Only one instance of each of these attributes shall be present.
    """
    VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_3.leg-4.2.1-3.prohibited_duplicate_attribute_present'
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT],
            pdu_class=rfc5280.Name
        )

    def validate(self, node):
        attr_counts = name.get_name_attribute_counts(node)

        for a in _REQUIRED_ATTRIBUTES:
            if attr_counts[a] > 1:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT,
                    f'Prohibited duplicate attribute present: {a}'
                )


class LegalPersonOrganizationAttributesEqualityValidator(validation.Validator):
    """
    LEG-4.2.1-6: The organizationIdentifier attribute shall contain an identification of the subject organization
    different from the organization name.
    """
    VALIDATION_ORGID_ORGNAME_ATTRIBUTE_VALUES_EQUAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_3.leg-4.2.1-6.organization_id_and_organization_name_attribute_values_equal'
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_ORGID_ORGNAME_ATTRIBUTE_VALUES_EQUAL],
            pdu_class=rfc5280.Name
        )

    @classmethod
    def _get_dirstring_attribute_value(cls, node):
        try:
            _, value_node = node.children['value'].child
            _, decoded_value_node = value_node.child

            return str(decoded_value_node.pdu)
        except ValueError:
            return None

    def validate(self, node):
        # only get the first instance of the attributes
        orgname_attr_and_idx = next(
            iter(name.get_name_attributes_by_type(node, rfc5280.id_at_organizationName)), None
        )
        orgid_attr_and_idx = next(
            iter(name.get_name_attributes_by_type(node, x520_name.id_at_organizationIdentifier)), None
        )

        if orgname_attr_and_idx and orgid_attr_and_idx:
            orgname_attr, _ = orgname_attr_and_idx
            orgid_attr, _ = orgid_attr_and_idx

            orgname = self._get_dirstring_attribute_value(orgname_attr)
            orgid = self._get_dirstring_attribute_value(orgid_attr)

            # if any of the attributes were not decoded, then return early
            if orgname is None or orgid is None:
                return

            if orgname.casefold() == orgid.casefold():
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_ORGID_ORGNAME_ATTRIBUTE_VALUES_EQUAL,
                    f'Organization name and identifier attribute values are equal: "{orgname}"'
                )
