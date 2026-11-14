"""小型显示过滤器：递归下降解析，不通过 eval 执行表达式。"""
from __future__ import annotations

import ipaddress
import operator
import re

_TOKEN = re.compile(r"""\s*(>=|<=|==|!=|&&|\|\||[()!<>]|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s()!<>=&|'\"]+)""")
_COMPARE = {'==': operator.eq, '!=': operator.ne, '>': operator.gt, '<': operator.lt,
            '>=': operator.ge, '<=': operator.le}


def compile_display_filter(expression):
    expression = expression.strip()
    if not expression:
        return lambda packet: True
    if len(expression) > 2048:
        raise ValueError('过滤表达式过长（最多2048字符）。')
    tokens, pos = [], 0
    while pos < len(expression):
        match = _TOKEN.match(expression, pos)
        if not match:
            raise ValueError('无法识别的过滤字符：' + expression[pos:pos + 16])
        tokens.append(match.group(1))
        pos = match.end()
    if len(tokens) > 256:
        raise ValueError('过滤表达式过于复杂。')
    index = 0

    def peek():
        return tokens[index].lower() if index < len(tokens) else ''

    def take():
        nonlocal index
        if index >= len(tokens):
            raise ValueError('过滤表达式不完整。')
        result = tokens[index]
        index += 1
        return result

    def unquote(value):
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '\"\'':
            return re.sub(r'\\([\\\"\'])', r'\1', value[1:-1])
        return value

    def atom():
        if peek() == '(':
            take()
            result = parse_or()
            if take() != ')':
                raise ValueError('过滤表达式括号不匹配。')
            return result
        name = take().lower()
        protocol_names = {'all', 'http', 'tcp', 'udp', 'ipv4', 'ip', 'ipv6', 'icmp', 'icmpv6', 'arp', 'dns', 'tls'}
        if name in protocol_names:
            def protocol(packet):
                if name == 'all':
                    return True
                if name in ('ip', 'ipv4'):
                    return packet.network == 'IPv4' if name == 'ipv4' else packet.network in ('IPv4', 'IPv6')
                if name == 'icmp':
                    return packet.transport in ('ICMP', 'ICMPv6')
                return name.upper() in (packet.protocol.upper(), packet.transport.upper(), packet.network.upper())
            return protocol
        if name == 'contains':
            value = take()
            if value.lower() in {'(', ')', '!', 'and', 'or', 'not', '&&', '||'} | set(_COMPARE):
                raise ValueError('contains 后需要文本；搜索语法符号时请使用引号。')
            needle = unquote(value).encode('utf-8')
            return lambda packet: needle in packet.raw
        address_fields = {'ip.src', 'ip.dst', 'ip.addr'}
        port_fields = {'port', 'tcp.port', 'udp.port', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport'}
        if name not in address_fields | port_fields | {'length'}:
            raise ValueError('未知的协议或字段：' + name)
        operation = take()
        if operation not in _COMPARE:
            raise ValueError('字段后需要比较运算符，例如 == 或 >=。')
        value = unquote(take())
        if name in address_fields:
            if operation not in ('==', '!='):
                raise ValueError('IP 地址仅支持 == 和 !=。')
            try:
                expected = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError('无效的 IP 地址：' + value) from exc
        else:
            try:
                expected = int(value)
            except ValueError as exc:
                raise ValueError('端口和长度需要整数。') from exc
            if expected < 0 or (name in port_fields and expected > 65535):
                raise ValueError('端口或长度超出有效范围。')

        def compare(packet):
            if name in address_fields:
                values = [packet.src] if name == 'ip.src' else [packet.dst] if name == 'ip.dst' else [packet.src, packet.dst]
                normalized = []
                for value in values:
                    try:
                        normalized.append(ipaddress.ip_address(value))
                    except ValueError:
                        pass
                if not normalized:
                    return False
                return expected not in normalized if operation == '!=' else expected in normalized
            if name == 'length':
                values = [packet.wire_length]
            else:
                if name.startswith('tcp.') and packet.transport != 'TCP':
                    return False
                if name.startswith('udp.') and packet.transport != 'UDP':
                    return False
                if name == 'port' and packet.transport not in ('TCP', 'UDP'):
                    return False
                values = [packet.src_port] if name.endswith('srcport') else [packet.dst_port] if name.endswith('dstport') else [packet.src_port, packet.dst_port]
                values = [v for v in values if v is not None]
            return all(_COMPARE[operation](v, expected) for v in values) if operation == '!=' else any(_COMPARE[operation](v, expected) for v in values)
        return compare

    def parse_not():
        if peek() in ('not', '!'):
            take()
            operand = parse_not()
            return lambda packet: not operand(packet)
        return atom()

    def parse_and():
        left = parse_not()
        while peek() in ('and', '&&'):
            take()
            right = parse_not()
            left = (lambda a, b: lambda packet: a(packet) and b(packet))(left, right)
        return left

    def parse_or():
        left = parse_and()
        while peek() in ('or', '||'):
            take()
            right = parse_and()
            left = (lambda a, b: lambda packet: a(packet) or b(packet))(left, right)
        return left

    try:
        result = parse_or()
    except RecursionError as exc:
        raise ValueError('过滤表达式嵌套过深。') from exc
    if index != len(tokens):
        raise ValueError('多余的过滤内容：' + tokens[index])
    return result
