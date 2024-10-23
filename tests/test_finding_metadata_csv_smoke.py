import csv
from os import path


def _test_csv(filename, expected_fieldnames):
    cur_dir = path.dirname(__file__)
    filename = path.join(cur_dir, "..", filename)

    with open(filename, "r", encoding="utf8") as csvfile:
        reader = csv.DictReader(csvfile, restkey="extra")

        assert reader.fieldnames == expected_fieldnames

        for row_idx, row in enumerate(reader):
            lineno = row_idx + 1 + 1  # 1-based index and header row

            extra = row.pop("extra", None)
            assert extra is None, f'Row "{row}" (line {lineno}) has extra fields'

            assert all(
                c is not None for c in row.values()
            ), f'Row "{row}" (line {lineno}) has a None value'


def test_cabf_smime_finding_metadata():
    _test_csv(
        "pkilint/cabf/smime/finding_metadata.csv",
        ["severity", "code", "source", "description"],
    )


def test_cabf_serverauth_finding_metadata():
    _test_csv(
        "pkilint/cabf/serverauth/finding_metadata.csv",
        ["severity", "code", "description"],
    )


def test_etsi_finding_metadata():
    _test_csv("pkilint/etsi/finding_metadata.csv", ["severity", "code", "description"])
