from pkilint.etsi.asn1 import en_319_412_5, ts_119_495


ETSI_QC_STATEMENTS_MAPPINGS = {
    en_319_412_5.id_etsi_qcs_QcCompliance: None,
    en_319_412_5.id_etsi_qcs_QcLimitValue: en_319_412_5.QcEuLimitValue(),
    en_319_412_5.id_etsi_qcs_QcRetentionPeriod: en_319_412_5.QcEuRetentionPeriod(),
    en_319_412_5.id_etsi_qcs_QcSSCD: None,
    en_319_412_5.id_etsi_qcs_QcPDS: en_319_412_5.QcEuPDS(),
    en_319_412_5.id_etsi_qcs_QcType: en_319_412_5.QcType(),
    en_319_412_5.id_etsi_qcs_QcCClegislation: en_319_412_5.QcCClegislation(),
    ts_119_495.id_etsi_psd2_qcStatement: ts_119_495.PSD2QcType(),
}
