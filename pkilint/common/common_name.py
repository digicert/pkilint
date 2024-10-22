import ipaddress
import typing

from pyasn1_alt_modules import rfc5280

from pkilint import validation, document
from pkilint.pkix import general_name


class CommonNameValidator(validation.Validator):
    def __init__(
        self,
        allowed_general_name_types: typing.Set[str],
        validation_unknown_value_source: validation.ValidationFinding,
    ):
        super().__init__(
            validations=[validation_unknown_value_source],
            pdu_class=rfc5280.X520CommonName,
        )

        self._allowed_general_name_types = allowed_general_name_types
        self._validation_unknown_value_source = validation_unknown_value_source

    def validate(self, node):
        # unparsed CN, return
        if not any(node.children):
            return

        _, value_node = node.child
        value_str = str(value_node.pdu)

        san_ext_and_idx = node.document.get_extension_by_oid(
            rfc5280.id_ce_subjectAltName
        )

        if san_ext_and_idx is None:
            raise validation.ValidationFindingEncountered(
                self._validation_unknown_value_source,
                f'Unknown source for value of common name: "{value_str}"',
            )

        san_ext_node, _ = san_ext_and_idx

        try:
            san_value_node = san_ext_node.navigate("extnValue.subjectAltName")
        except document.PDUNavigationFailedError:
            # unparsed SAN extension, return
            return

        for gn in san_value_node.children.values():
            gn_type, gn_value = gn.child

            if gn_type not in self._allowed_general_name_types:
                continue

            if gn_type == general_name.GeneralNameTypeName.DNS_NAME:
                if str(gn_value.pdu) == value_str:
                    return
            elif gn_type == general_name.GeneralNameTypeName.IP_ADDRESS:
                address_octets = gn_value.pdu.asOctets()

                if len(address_octets) == 4:
                    ip_addr = ipaddress.IPv4Address(address_octets)
                elif len(address_octets) == 16:
                    ip_addr = ipaddress.IPv6Address(address_octets)
                else:
                    # Whoa, Nellie! Let the PKIX validator complain about this one
                    continue

                if str(ip_addr) == value_str:
                    return

        raise validation.ValidationFindingEncountered(
            self._validation_unknown_value_source,
            f'Unknown source for value of common name: "{value_str}"',
        )
