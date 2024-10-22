from pyasn1_alt_modules import rfc3739

from pkilint import document
from pkilint.etsi.asn1 import en_319_412_5, ts_119_495, en_319_411_2

ETSI_QC_STATEMENTS_MAPPINGS = {
    en_319_412_5.id_etsi_qcs_QcCompliance: document.ValueDecoder.VALUE_NODE_ABSENT,
    en_319_412_5.id_etsi_qcs_QcLimitValue: en_319_412_5.QcEuLimitValue(),
    en_319_412_5.id_etsi_qcs_QcRetentionPeriod: en_319_412_5.QcEuRetentionPeriod(),
    en_319_412_5.id_etsi_qcs_QcSSCD: document.ValueDecoder.VALUE_NODE_ABSENT,
    en_319_412_5.id_etsi_qcs_QcPDS: en_319_412_5.QcEuPDS(),
    en_319_412_5.id_etsi_qcs_QcType: en_319_412_5.QcType(),
    en_319_412_5.id_etsi_qcs_QcCClegislation: en_319_412_5.QcCClegislation(),
    ts_119_495.id_etsi_psd2_qcStatement: ts_119_495.PSD2QcType(),
    rfc3739.id_qcs_pkixQCSyntax_v1: document.OptionalAsn1TypeWrapper(
        rfc3739.SemanticsInformation()
    ),
    rfc3739.id_qcs_pkixQCSyntax_v2: document.OptionalAsn1TypeWrapper(
        rfc3739.SemanticsInformation()
    ),
}
