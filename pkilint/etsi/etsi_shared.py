import enum
from typing import Optional

from pyasn1_alt_modules import rfc5280

from pkilint import validation, document
from pkilint.itu import bitstring
from pkilint.pkix.certificate.certificate_extension import KeyUsageBitName


class KeyUsageValidator(validation.Validator):
    """
    NAT-4.3.2-1: The key usage extension shall be present and shall contain one (and only one) of the key usage settings
    defined in table 1 (A, B, C, D, E or F).
    """

    VALIDATION_UNKNOWN_KEY_USAGE_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.nat-4.3.2-1.unknown_key_usage_setting",
    )

    """
    NAT-4.3.2-1: ... Type A, C or E should be used to avoid mixed usage of keys.
    """
    VALIDATION_MIXED_KEY_USAGE_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "etsi.en_319_412_2.nat-4.3.2-1.mixed_key_usage_setting",
    )

    _ALL_KUS = {str(n) for n in rfc5280.KeyUsage.namedValues}

    def __init__(
        self,
        is_content_commitment_type: Optional[bool],
        validation_invalid_content_commitment_setting: validation.ValidationFinding,
        validation_non_preferred_content_commitment_setting: validation.ValidationFinding,
    ):
        super().__init__(
            validations=[
                self.VALIDATION_UNKNOWN_KEY_USAGE_SETTING,
                self.VALIDATION_MIXED_KEY_USAGE_SETTING,
                validation_invalid_content_commitment_setting,
                validation_non_preferred_content_commitment_setting,
            ],
            pdu_class=rfc5280.KeyUsage,
        )

        self._is_content_commitment_type = is_content_commitment_type

        self._validation_invalid_content_commitment_setting = (
            validation_invalid_content_commitment_setting
        )
        self._validation_non_preferred_content_commitment_setting = (
            validation_non_preferred_content_commitment_setting
        )

    class KeyUsageSetting(enum.Enum):
        A = ({KeyUsageBitName.NON_REPUDIATION}, set())
        B = (
            {KeyUsageBitName.NON_REPUDIATION, KeyUsageBitName.DIGITAL_SIGNATURE},
            set(),
        )
        C = ({KeyUsageBitName.DIGITAL_SIGNATURE}, set())
        D = (
            {KeyUsageBitName.DIGITAL_SIGNATURE},
            {KeyUsageBitName.KEY_AGREEMENT, KeyUsageBitName.KEY_ENCIPHERMENT},
        )
        E = (set(), {KeyUsageBitName.KEY_AGREEMENT, KeyUsageBitName.KEY_ENCIPHERMENT})
        F = (
            {KeyUsageBitName.NON_REPUDIATION, KeyUsageBitName.DIGITAL_SIGNATURE},
            {KeyUsageBitName.KEY_AGREEMENT, KeyUsageBitName.KEY_ENCIPHERMENT},
        )

    _CONTENT_COMMITMENT_SETTINGS = {
        KeyUsageSetting.A,
        KeyUsageSetting.B,
        KeyUsageSetting.F,
    }
    _NON_CONTENT_COMMITMENT_SETTINGS = {
        s for s in KeyUsageSetting
    } - _CONTENT_COMMITMENT_SETTINGS

    _MIXED_USE_SETTINGS = {KeyUsageSetting.B, KeyUsageSetting.D, KeyUsageSetting.F}

    @classmethod
    def _detect_setting(
        cls, key_usage_node: document.PDUNode
    ) -> Optional[KeyUsageSetting]:
        asserted_bits = {
            k for k in cls._ALL_KUS if bitstring.has_named_bit(key_usage_node, k)
        }

        for setting in cls.KeyUsageSetting:
            n_of_n_required_bits, one_of_n_required_bits = setting.value

            allowed_bits = n_of_n_required_bits | one_of_n_required_bits

            if (
                asserted_bits >= n_of_n_required_bits
                and (
                    len(one_of_n_required_bits & asserted_bits) == 1
                    or not one_of_n_required_bits
                )
                and not any(asserted_bits - allowed_bits)
            ):
                return setting

        return None

    def validate(self, node):
        setting = self._detect_setting(node)

        if setting is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNKNOWN_KEY_USAGE_SETTING
            )

        if self._is_content_commitment_type is not None:
            if self._is_content_commitment_type:
                if setting not in self._CONTENT_COMMITMENT_SETTINGS:
                    raise validation.ValidationFindingEncountered(
                        self._validation_invalid_content_commitment_setting
                    )
                elif setting != self.KeyUsageSetting.A:
                    raise validation.ValidationFindingEncountered(
                        self._validation_non_preferred_content_commitment_setting
                    )
            elif (
                not self._is_content_commitment_type
                and setting not in self._NON_CONTENT_COMMITMENT_SETTINGS
            ):
                raise validation.ValidationFindingEncountered(
                    self._validation_invalid_content_commitment_setting
                )

        if setting in self._MIXED_USE_SETTINGS:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_MIXED_KEY_USAGE_SETTING
            )


VALIDATION_INTERNAL_DOMAIN_NAME = validation.ValidationFinding(
    validation.ValidationFindingSeverity.ERROR, "etsi.internal_domain_name"
)


VALIDATION_INTERNAL_IP_ADDRESS = validation.ValidationFinding(
    validation.ValidationFindingSeverity.ERROR, "etsi.internal_ip_address"
)
