import ipaddress
import socket

ALLOWED_IPV4 = tuple(
    ipaddress.ip_network(block)
    for block in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
)


class UnsafeTargetError(ValueError):
    pass


def resolve_safe_target(target: str) -> str:
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"Target {target!r} could not be resolved: {exc}") from None
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise UnsafeTargetError(f"Target {target!r} resolved to no addresses")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        allowed = (
            any(ip in network for network in ALLOWED_IPV4)
            if ip.version == 4
            else ip.is_loopback or ip.is_link_local
        )
        if not allowed:
            raise UnsafeTargetError(
                f"Refusing public target {address}; only loopback, RFC1918 private, or link-local targets are allowed"
            )
    return sorted(addresses)[0]
