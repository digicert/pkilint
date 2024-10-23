import datetime

from pkilint.pkix.certificate import certificate_transparency
from pkilint import document
from pyasn1_alt_modules import rfc6962


_SCT_LIST_OCTETS = "016a007700eecdd064d5db1acec55cb79db4cd13a23287467cbcecdec351485946711fb59b0000018650dd1bfa0000040300483046022100e416aed3e22cba829fa979f24bc69452ed4de087cc50ca69b1b48f05773a94eb022100b59fc3f9cb0fadd060f2301b710572120dbd651f07a99c534b76951204a6bf2e00760048b0e36bdaa647340fe56a02fa9d30eb1c5201cb56dd2c81d9bbbfab39d884730000018650dd1c2b000004030047304502201e3c60327e2051f5d6e1af7d4df597c4482e46576b860537324f250436b1f7b7022100fc097ec07c03832636bda75beb1d1359f662208e6d6fb70d31ebdbf511ee5bd40077003b5377753e2db9804e8b305b06fe403b67d84fc3f4c7bd000d2d726fe1fad4170000018650dd1c3a0000040300483046022100cce06bf4e674fba3926721538b2c0deb83f2b0dd052de2d1c8be63984b18ac36022100eed23b605a2308294e8233474a72a5162e4685136ddcda2580858007aab15147"


def test_sctlist_decode():
    sct_list = rfc6962.SignedCertificateTimestampList(hexValue=_SCT_LIST_OCTETS)

    validator = certificate_transparency.SctListExtensionDecodingValidator()

    node = document.PDUNode(None, "sctList", sct_list, None)
    validator.validate(node)

    decoded = getattr(sct_list, "decoded")

    assert len(decoded) == 3

    assert all((s.sct_version == 0 for s in decoded))

    assert all((len(s.extensions) == 0 for s in decoded))

    assert all(
        (s.hash_alg == certificate_transparency.HashAlgorithm.SHA256 for s in decoded)
    )

    assert all(
        (
            s.sig_alg == certificate_transparency.SignatureAlgorithm.ECDSA
            for s in decoded
        )
    )

    for actual, expected in zip(
        (s.log_id for s in decoded),
        (
            b"\xee\xcd\xd0d\xd5\xdb\x1a\xce\xc5\\\xb7\x9d\xb4\xcd\x13\xa22\x87F|\xbc\xec\xde\xc3QHYFq\x1f\xb5\x9b",
            b"H\xb0\xe3k\xda\xa6G4\x0f\xe5j\x02\xfa\x9d0\xeb\x1cR\x01\xcbV\xdd,\x81\xd9\xbb\xbf\xab9\xd8\x84s",
            b";Swu>-\xb9\x80N\x8b0[\x06\xfe@;g\xd8O\xc3\xf4\xc7\xbd\x00\r-ro\xe1\xfa\xd4\x17",
        ),
    ):
        assert actual == expected

    for actual, expected in zip(
        (s.timestamp_datetime for s in decoded),
        (
            datetime.datetime(
                2023, 2, 14, 16, 58, 33, 338000, tzinfo=datetime.timezone.utc
            ),
            datetime.datetime(
                2023, 2, 14, 16, 58, 33, 387000, tzinfo=datetime.timezone.utc
            ),
            datetime.datetime(
                2023, 2, 14, 16, 58, 33, 402000, tzinfo=datetime.timezone.utc
            ),
        ),
    ):
        assert actual == expected

    for actual, expected in zip(
        (s.signature for s in decoded),
        (
            b"0F\x02!\x00\xe4\x16\xae\xd3\xe2,\xba\x82\x9f\xa9y\xf2K\xc6\x94R\xedM\xe0\x87\xccP\xcai\xb1\xb4\x8f"
            b"\x05w:\x94\xeb\x02!\x00\xb5\x9f\xc3\xf9\xcb\x0f\xad\xd0`\xf20\x1bq\x05r\x12\r\xbde\x1f\x07\xa9"
            b"\x9cSKv\x95\x12\x04\xa6\xbf.",
            b"0E\x02 \x1e<`2~ Q\xf5\xd6\xe1\xaf}M\xf5\x97\xc4H.FWk\x86\x0572O%\x046\xb1\xf7\xb7\x02!\x00\xfc\t"
            b"~\xc0|\x03\x83&6\xbd\xa7[\xeb\x1d\x13Y\xf6b \x8emo\xb7\r1\xeb\xdb\xf5\x11\xee[\xd4",
            b"0F\x02!\x00\xcc\xe0k\xf4\xe6t\xfb\xa3\x92g!S\x8b,"
            b"\r\xeb\x83\xf2\xb0\xdd\x05-\xe2\xd1\xc8\xbec\x98K\x18\xac6\x02!\x00\xee\xd2;`Z#\x08)N\x823GJr\xa5"
            b"\x16.F\x85\x13m\xdc\xda%\x80\x85\x80\x07\xaa\xb1QG",
        ),
    ):
        assert actual == expected
