from types import SimpleNamespace

import pytest

from sniffer.filters import compile_display_filter


def packet(**changes):
    values = dict(network='IPv4', transport='TCP', protocol='HTTP', src='192.0.2.1',
                  dst='198.51.100.2', src_port=50000, dst_port=80, wire_length=100,
                  raw=b'GET /lab HTTP/1.1\r\n', payload=b'GET /lab HTTP/1.1\r\n',
                  summary='GET /lab HTTP/1.1')
    values.update(changes)
    return SimpleNamespace(**values)


def test_protocol_filters_include_lower_layers():
    p = packet()
    for expression in ('', 'http', 'tcp', 'ipv4', 'ip', 'all'):
        assert compile_display_filter(expression)(p)
    assert not compile_display_filter('udp')(p)


def test_logical_precedence_and_parentheses():
    assert compile_display_filter('udp or tcp and http')(packet())
    assert not compile_display_filter('(udp or tcp) and not http')(packet())
    assert compile_display_filter('icmp')(packet(transport='ICMPv6', protocol='ICMPv6', network='IPv6'))


def test_addresses_ports_lengths_and_quoted_content():
    p = packet()
    for expression in ('ip.src == 192.0.2.1', 'ip.addr == 198.51.100.2', 'port == 80',
                       'tcp.port == 50000 and length >= 100', 'contains "GET /lab"'):
        assert compile_display_filter(expression)(p)
    assert not compile_display_filter('udp.port == 80')(p)


@pytest.mark.parametrize('expression', ['tcp and', '(tcp', 'unknown', 'port == abc',
    '__import__("os")', 'tcp or or udp', 'ip.src == not-an-ip', 'tcp)', 'port == 70000',
    'contains "GET', "contains 'GET", 'contains )', 'contains (', 'contains !', 'contains and'])
def test_invalid_filter_is_rejected_without_eval(expression):
    with pytest.raises(ValueError):
        compile_display_filter(expression)
