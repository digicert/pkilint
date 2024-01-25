import binascii
import logging
import re
from typing import Callable, Mapping, Tuple, Type, Union, Optional, Dict, List

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type.base import Asn1Type
from pyasn1.type.univ import (ObjectIdentifier, SequenceOfAndSetOfBase, SequenceAndSetBase,
                              Choice, BitString
                              )


logger = logging.getLogger(__name__)

PATH_REGEX = re.compile(r'^((?P<doc_name>[^:]*):)?(?P<node_path>([^.]+\.)*[^.]+)?$')


try:
    from pyasn1_fasder import decode_der

    logging.info('Using pyasn1-fasder for ASN.1 DER decoding')
#    _USE_PYASN1_FASDER = True
    _USE_PYASN1_FASDER = False
except ImportError:
    _USE_PYASN1_FASDER = False


class PDUNavigationFailedError(Exception):
    """Represents the failure to find the requested node in a document."""

    def __init__(self, requested_path: str, traversed_path: str,
                 missing_node_name: str
                 ):
        """Creates an instance of an exception that represents a PDU node lookup failure.

        Args: requested_path: The requested path relative to the node which
        :py:method:`pkilint.document.PDUNode.navigate was called. traversed_path: The relative path that was able to
        be traversed, as those nodes exist. missing_node_name: The name of the node which could not be found.
        """
        self.requested_path = requested_path
        self.traversed_path = traversed_path
        self.missing_node_name = missing_node_name

    def __str__(self) -> str:
        return (f'Node with name "{self.missing_node_name}" does not exist at '
                f'"{self.traversed_path}" (requested path: "{self.requested_path}")'
                )


class Document(object):
    """Represents an ASN.1-encoded document."""

    def __init__(
            self, pdu_schema_instance: Asn1Type, substrate_source: str, substrate: bytes,
            name: Optional[str] = None,
            parent: Optional[Mapping[str, 'Document']] = None
    ):
        """Creates a new Document instance. It is not intended that this class be directly
        instantiated by user code; use a sub-class of this class instead.

        Args:
            pdu_schema_instance: A pyasn1 ASN.1 instance that represents the top-level ASN.1 schema for this document.
            substrate_source: The source of the document. This can be a URI, file name, or any other identifier.
            substrate: The raw DER-encoded document.
            name: An optional name given to the document. May be useful when a :py:meth:`pkilint.validation.Validator` requires multiple documents.
            parent: An optional collection of documents that are related.
        """
        self.pdu_schema_instance = pdu_schema_instance
        self.substrate = substrate
        self.substrate_source = substrate_source

        self.name = name
        self.parent = parent
        self.root = None

    def decode(self):
        """
            Decodes the DER-encoded substrate with the specified ASN.1 schema object.

            If the document does not conform to the schema, then this will fail.
        """
        if self.root is None:
            self.root = decode_substrate(self, self.substrate,
                                         self.pdu_schema_instance
                                         )

        return self.root

    def __repr__(self):
        return f'{self.root.name} document "{self.substrate_source}"'


class PDUNode(object):
    """Represents a node of a document."""

    def __init__(self, document: Document, name: str, pdu: Asn1Type,
                 parent: Optional['PDUNode']
                 ):
        """Creates a new instance representing a node within a document.

        Args:
            document: The document which contains this node.
            name: The name of the node. Generally will match the name of a component
            within an ASN.1 SEQUENCE.
            pdu: The underlying ASN.1 value.
            parent: The node which contains this node. In the case where the current node is the top-level node of a document, this will not be populated.
        """
        self.document = document
        self.name = name
        self.pdu = pdu
        self.parent = parent
        if self.parent is None:
            self.path = self.name
        else:
            self.path = f'{self.parent.path}.{self.name}'

        self.children = self._generate_child_nodes()

    @property
    def parents(self) -> List['PDUNode']:
        """All parent nodes up to the root of the document."""
        nodes = []
        node = self.parent
        while node is not None:
            nodes.append(node)
            node = node.parent

        return nodes

    @property
    def child(self) -> Tuple[str, 'PDUNode']:
        """The node name and node of the single child node.

        This property will fail if no child nodes or more than one child node is present.
        """
        if len(self.children) > 1:
            raise ValueError(f'"{self}" has multiple child nodes')
        elif len(self.children) == 0:
            raise ValueError(f'"{self}" has no child nodes')
        else:
            return next(iter(self.children.items()))

    def navigate(self, path: str) -> Union['PDUNode', Document]:
        """Navigates to a node or document (depending on the path specified).

        Elements within a path are separated by periods ("."). Paths may be absolute or relative. Relative paths can
        be relative to the current document or the current node, depending on the syntax used.

        Absolute paths begin with the document name followed by a colon (":"). If no sub-elements are specified,
        then the complete document matching the specified name is returned. For example: `subject:` returns the
        document named "subject". Absolute paths may also contain a node path following the document name and colon.

        Relative paths consist of a leading colon (which anchors the path to the root of the current document) and/or
        a node path.

        The node path element "^" navigates to the parent node.

        Args:
            path: The requested path.
        """
        requested_path = path

        m = PATH_REGEX.match(path)

        if m is None:
            raise ValueError(f'Invalid path syntax: "{path}"')

        doc_name = m.group('doc_name')
        if m.group('node_path') is None:
            node_path_parts = []
        else:
            node_path_parts = m.group('node_path').split('.')

        if doc_name is None:
            node = self
        else:
            if doc_name == '':
                doc = self.document

                if len(node_path_parts) == 0:
                    return doc
            else:
                if self.document.parent is None or doc_name not in self.document.parent:
                    raise PDUNavigationFailedError(requested_path, '', doc_name)

                doc = self.document.parent[doc_name]

            root_name = node_path_parts[0]
            if doc.root.name != root_name:
                raise PDUNavigationFailedError(requested_path, doc_name, root_name)

            node = doc.root
            node_path_parts = node_path_parts[1:]

        for part in node_path_parts:
            if part == '^':
                node = node.parent
            else:
                try:
                    node = node.children[part]
                except KeyError:
                    raise PDUNavigationFailedError(requested_path, node.path, part)

        return node

    def _generate_child_nodes(self):
        if isinstance(self.pdu, Choice):
            name = self.pdu.getName()
            return {name: PDUNode(
                self.document, name, self.pdu.getComponent(), self
            )
            }
        elif isinstance(self.pdu, SequenceOfAndSetOfBase):
            return {
                str(i): PDUNode(
                    self.document, str(i), component, self
                )
                for i, component in enumerate(self.pdu)
            }
        elif isinstance(self.pdu, SequenceAndSetBase):
            return {name: PDUNode(self.document, name, value, self)
                    for name, value in self.pdu.items()
                    if value.isValue
                    }
        else:
            return {}

    def __repr__(self):
        if self.document is not None and self.document.name is not None:
            path = f'{self.document.name}:{self.path}'
        else:
            path = self.path
        return f'{self.pdu.__class__.__name__} @ {path}'


class NodeVisitor(object):
    def __init__(self, *,
                 path: str = None,
                 path_re: re.Pattern = None,
                 pdu_class: Type[Asn1Type] = None,
                 pdu_supertype: Asn1Type = None,
                 predicate: Callable[[PDUNode], bool] = None
                 ):
        self._path = path
        self._path_re = path_re
        self._pdu_class = pdu_class
        self._pdu_supertype = pdu_supertype
        self._predicate = predicate

    def match(self, node: PDUNode) -> bool:
        if self._path is not None and self._path != node.path:
            return False
        if self._path_re is not None and self._path_re.match(node.path) is None:
            return False
        if self._pdu_class is not None and not isinstance(node.pdu, self._pdu_class):
            return False
        if self._pdu_supertype is not None and not self._pdu_supertype.isSuperTypeOf(node.pdu):
            return False
        if self._predicate is not None and not self._predicate(node):
            return False

        return True


class ValueDecodingFailedError(Exception):
    def __init__(self, value_node: PDUNode, type_oid: ObjectIdentifier,
                 pdu_type: Optional[Asn1Type], message: str
                 ):
        self.value_node = value_node
        self.type_oid = type_oid
        self.pdu_type = pdu_type
        self.message = message


class ValueDecoder(object):
    _BITSTRING_SCHEMA_OBJ = BitString()

    VALUE_NODE_ABSENT = object()

    def __init__(self, *, type_path: str, value_path: str,
                 type_mappings: Dict[ObjectIdentifier, Optional[Asn1Type]], default: Optional[Asn1Type] = None):
        self.type_path = type_path
        self.value_path = value_path
        self.type_mappings = type_mappings.copy()
        self.default = default

    def filter_value(self, node, type_node, value_node, pdu_type):
        if self._BITSTRING_SCHEMA_OBJ.isSuperTypeOf(value_node.pdu):
            return value_node.pdu.asOctets()
        else:
            return value_node.pdu

    def __call__(self, node):
        type_node = node.navigate(self.type_path)

        try:
            value_node = node.navigate(self.value_path)
        except PDUNavigationFailedError:
            value_node = None

        pdu_type = self.type_mappings.get(type_node.pdu, self.default)

        if pdu_type is not None:
            # value node must be absent, but it exists
            if pdu_type is self.VALUE_NODE_ABSENT and value_node is not None:
                raise ValueDecodingFailedError(
                    value_node, type_node.pdu, pdu_type,
                    'Value node is present, but the ASN.1 schema specifies that it must be absent'
                )
            # value node must be present, but it doesn't exist
            if pdu_type is not self.VALUE_NODE_ABSENT and value_node is None:
                raise ValueDecodingFailedError(
                    node, type_node.pdu, pdu_type,
                    'Value node is absent, but the ASN.1 schema specifies that it must be present'
                )

        if pdu_type is self.VALUE_NODE_ABSENT or pdu_type is None:
            return

        value_octets = self.filter_value(node, type_node, value_node, pdu_type)

        try:
            decode_substrate(value_node.document, value_octets,
                             pdu_type, value_node
                             )
        except (PyAsn1Error, ValueError) as e:
            raise ValueDecodingFailedError(
                value_node, type_node.pdu, pdu_type, str(e)
            )


def get_node_name_for_pdu(pdu: Asn1Type) -> str:
    name = pdu.__class__.__name__
    # convert PDU class name to camelCase
    return name[0].lower() + name[1:]


def get_document_by_name(node: PDUNode, document_name: str) -> Document:
    """Retrieves the document with the specified name"""
    return node.document.parent[document_name]


def decode_substrate(source_document: Document, substrate: bytes,
                     pdu_instance: Asn1Type, parent_node: Optional[PDUNode] = None) -> PDUNode:
    if parent_node is not None and any(parent_node.children):
        logger.debug("%s has child node; not creating new PDU node",
                     parent_node.path
                     )
        return next(iter(parent_node.children.values()))

    if _USE_PYASN1_FASDER:
        decoded, _ = decode_der(substrate, asn1Spec=pdu_instance)

        decoded_pdu_name = get_node_name_for_pdu(decoded)
    else:
        decoded, rest = decode(substrate, asn1Spec=pdu_instance)

        decoded_pdu_name = get_node_name_for_pdu(decoded)

        if len(rest) > 0:
            raise ValueError(
                "Unexpected {} octets following {} DER in {}: {}".format(
                    len(rest), decoded_pdu_name, source_document.substrate_source,
                    binascii.hexlify(rest).decode('us-ascii')
                )
            )

        encoded = encode(decoded)
        if encoded != substrate:
            type_name = decoded.__class__.__name__
            raise ValueError(
                f'Substrate of type "{type_name}" is not DER-encoded'
            )

    node = PDUNode(source_document, decoded_pdu_name, decoded, parent_node)

    if parent_node is not None:
        parent_node.children[decoded_pdu_name] = node
        logger.debug("Appended %s node to %s", node.name,
                     parent_node.path
                     )

    return node


def get_re_for_path_glob(path_glob: str) -> re.Pattern:
    return re.compile(
        path_glob.replace('.', r'\.').replace('?', r'\w').replace('*', r'\w*')
    )
