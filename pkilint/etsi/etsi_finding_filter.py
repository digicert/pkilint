from pkilint import finding_filter
from pkilint.cabf.serverauth import serverauth_subscriber
from pkilint.etsi.asn1 import ts_119_495 as ts_119_495_asn1


class Psd2CabfServerauthValidityPeriodFilter(finding_filter.FindingDescriptionFilter):
    _TARGET_VALIDATIONS = {
        serverauth_subscriber.SubscriberValidityPeriodValidator.VALIDATION_VALIDITY_PERIOD_EXCEEDS_397_DAYS,
        serverauth_subscriber.SubscriberValidityPeriodValidator.VALIDATION_VALIDITY_PERIOD_EXCEEDS_398_DAYS,
    }

    def filter(self, result, finding_description):
        if finding_description.finding in self._TARGET_VALIDATIONS:
            """
            OVR-6.1-3: TSPs issuing certificates for EU PSD2 may use the following policy identifier to augment the
            policy requirements associated with policy identifier QEVCP-w or QNCP-w as specified in
            ETSI EN 319 411-2 [5] giving precedence to the requirements defined in the present document.
            """
            return ts_119_495_asn1.qcp_web_psd2 not in result.node.document.policy_oids
        else:
            return True
