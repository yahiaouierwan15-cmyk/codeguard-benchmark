"""XXE trigger — VP-005 (CWE-611)."""
from lxml import etree
from flask import request


def vuln_xxe():
    xml = request.data
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    tree = etree.fromstring(xml, parser)
    return etree.tostring(tree)


def vuln_xxe_dtd():
    xml = request.data
    parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
    return etree.fromstring(xml, parser)
