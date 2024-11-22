def has_named_bit(node, bit_name):
    bit = node.pdu.namedValues[bit_name]
    return len(node.pdu) > bit and node.pdu[bit] != 0


def get_asserted_bit_set(node):
    return {str(b) for b in node.pdu.namedValues if has_named_bit(node, str(b))}
