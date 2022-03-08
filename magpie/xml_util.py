"""
Define a default XML parser that avoids XXE injection.

Package :mod:`lxml` is employed directly even though some linters (e.g.: ``bandit``) report to employ ``defusedxml``
instead, because that package's extension with ``lxml`` is marked as deprecated.

.. seealso::
    https://pypi.org/project/defusedxml/#defusedxml-lxml

To use the module, import is as if importing ``lxml.etree``:

.. code-block:: python

    from weaver.xml_util import XML  # ElementTree
    from weaver import xml_util

    data = xml_util.fromstring("<xml>content</xml>")
"""

from typing import TYPE_CHECKING

from lxml import etree as lxml_etree  # nosec: B410  # flagged known issue, this is what the applied fix below is about

if TYPE_CHECKING:
    from lxml.etree._FeedParser import _FeedParser as Parser  # noqa # pylint: disable=W0212

XML_PARSER = lxml_etree.XMLParser(
    # security fix: XML external entity (XXE) injection
    #   https://lxml.de/parsing.html#parser-options
    #   https://nvd.nist.gov/vuln/detail/CVE-2021-39371
    # based on:
    #   https://github.com/geopython/pywps/pull/616
    resolve_entities=False,
    # avoid failing parsing if some characters are not correctly escaped
    # based on:
    #   https://stackoverflow.com/a/57450722/5936364
    recover=True,  # attempt, no guarantee
)

tostring = lxml_etree.tostring
Element = lxml_etree.Element
ParseError = lxml_etree.ParseError

# define this type here so that code can use it for actual logic without repeating 'noqa'
XML = lxml_etree._Element  # noqa # pylint: disable=W0212

# save a local reference to method employed by OWSLib directly called
_lxml_fromstring = lxml_etree.fromstring


def fromstring(text, parser=XML_PARSER):
    # type: (str, Parser) -> XML
    """
    Drop in replacement for :func:`lxml.etree.fromstring` using a secure :term:`XML` parser.
    """
    return _lxml_fromstring(text, parser=parser)  # nosec: B410,B320  # safe use if using secure parser


def strip_namespace(tree):
    # type: (XML) -> None
    """
    Strip the namespace component from all tags in the specified :term:`XML` tree.
    """
    for node in tree.iter():
        try:
            has_namespace = node.tag.startswith("{")
        except AttributeError:
            continue  # node.tag is not a string (node is a comment or similar)
        if has_namespace:
            node.tag = node.tag.split("}", 1)[1]
