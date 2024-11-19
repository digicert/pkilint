from pyasn1_alt_modules import rfc3279, rfc5480, rfc5280

from pkilint.pkix import key
from pkilint import validation


class RsaKeyValidator(validation.Validator):
    VALIDATION_RSA_MODULUS_INVALID_LENGTH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.rsa_modulus_invalid_length"
    )

    VALIDATION_RSA_MODULUS_HAS_SMALL_PRIME_FACTOR = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.rsa_modulus_has_small_prime_factor",
    )

    VALIDATION_RSA_EXPONENT_PROHIBITED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.rsa_exponent_prohibited_value"
    )

    VALIDATION_RSA_EXPONENT_NOT_IN_RECOMMENDED_RANGE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.rsa_exponent_not_in_recommended_range",
    )

    _PRIMES_UNDER_752 = {
        2,
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
        101,
        103,
        107,
        109,
        113,
        127,
        131,
        137,
        139,
        149,
        151,
        157,
        163,
        167,
        173,
        179,
        181,
        191,
        193,
        197,
        199,
        211,
        223,
        227,
        229,
        233,
        239,
        241,
        251,
        257,
        263,
        269,
        271,
        277,
        281,
        283,
        293,
        307,
        311,
        313,
        317,
        331,
        337,
        347,
        349,
        353,
        359,
        367,
        373,
        379,
        383,
        389,
        397,
        401,
        409,
        419,
        421,
        431,
        433,
        439,
        443,
        449,
        457,
        461,
        463,
        467,
        479,
        487,
        491,
        499,
        503,
        509,
        521,
        523,
        541,
        547,
        557,
        563,
        569,
        571,
        577,
        587,
        593,
        599,
        601,
        607,
        613,
        617,
        619,
        631,
        641,
        643,
        647,
        653,
        659,
        661,
        673,
        677,
        683,
        691,
        701,
        709,
        719,
        727,
        733,
        739,
        743,
        751,
    }

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_RSA_MODULUS_INVALID_LENGTH,
                self.VALIDATION_RSA_MODULUS_HAS_SMALL_PRIME_FACTOR,
                self.VALIDATION_RSA_EXPONENT_PROHIBITED,
                self.VALIDATION_RSA_EXPONENT_NOT_IN_RECOMMENDED_RANGE,
            ],
            pdu_class=rfc3279.RSAPublicKey,
        )

    def validate(self, node):
        modulus = int(node.children["modulus"].pdu)
        modulus_len = modulus.bit_length()
        exponent = int(node.children["publicExponent"].pdu)

        results = []

        if modulus_len < 2048 or modulus_len % 8 != 0:
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_RSA_MODULUS_INVALID_LENGTH,
                    f"Invalid modulus length: {modulus_len}",
                )
            )

        small_prime = next(
            filter(lambda p: modulus % p == 0, self._PRIMES_UNDER_752), None
        )

        if small_prime is not None:
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_RSA_MODULUS_HAS_SMALL_PRIME_FACTOR,
                    f"Modulus has prime factor less than 752: {small_prime}",
                )
            )

        if exponent % 2 == 0:
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_RSA_EXPONENT_PROHIBITED,
                    f"Exponent is not odd: {exponent}",
                )
            )
        elif exponent < 3:
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_RSA_EXPONENT_PROHIBITED,
                    f"Exponent is less than 3: {exponent}",
                )
            )

        if exponent < ((1 << 16) + 1) or exponent > ((1 << 256) - 1):
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_RSA_EXPONENT_NOT_IN_RECOMMENDED_RANGE,
                    f"Exponent is out of recommended range: {exponent}",
                )
            )

        return validation.ValidationResult(self, node, results)


class EcdsaKeyValidator(validation.Validator):
    VALIDATION_KEY_VALIDATION_FAILED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING, "cabf.ecdsa_key_validation_failed"
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_KEY_VALIDATION_FAILED],
            pdu_class=rfc5280.SubjectPublicKeyInfo,
            predicate=lambda n: n.navigate("algorithm.algorithm").pdu
            == rfc5480.id_ecPublicKey,
        )

    def validate(self, node):
        try:
            key_obj = key.convert_spki_to_object(node)

            if key_obj is None:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_KEY_VALIDATION_FAILED, "Unsupported key type"
                )
        except ValueError as e:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_KEY_VALIDATION_FAILED, str(e)
            )
