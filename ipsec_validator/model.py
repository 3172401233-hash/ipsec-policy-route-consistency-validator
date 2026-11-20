"""Data model for the offline IPsec consistency validator."""

from dataclasses import dataclass, field
from ipaddress import ip_network, ip_address
from typing import Optional, Tuple

DIRECTION_OUTBOUND = "outbound"
DIRECTION_INBOUND = "inbound"

ACTION_BYPASS = "bypass"
ACTION_PROTECT = "protect"
ACTION_DISCARD = "discard"

ACTION_NO_MATCH = "no-match"
ACTION_CONFLICT = "conflict"


def _to_network(value):
    if isinstance(value, str):
        return ip_network(value, strict=False)
    return value


@dataclass(frozen=True)
class Selector:
    """A traffic selector: 5-tuple range plus direction."""

    src: object
    dst: object
    protocol: Optional[str] = None  # None means "any"
    src_ports: Tuple[int, int] = (0, 65535)
    dst_ports: Tuple[int, int] = (0, 65535)
    direction: str = DIRECTION_OUTBOUND

    def __post_init__(self):
        object.__setattr__(self, "src", _to_network(self.src))
        object.__setattr__(self, "dst", _to_network(self.dst))
        if self.protocol is not None:
            object.__setattr__(self, "protocol", str(self.protocol).lower())

    def mirrored(self) -> "Selector":
        """Return the selector with src/dst swapped (for symmetry checks)."""
        return Selector(
            src=self.dst,
            dst=self.src,
            protocol=self.protocol,
            src_ports=self.dst_ports,
            dst_ports=self.src_ports,
            direction=(
                DIRECTION_INBOUND
                if self.direction == DIRECTION_OUTBOUND
                else DIRECTION_OUTBOUND
            ),
        )

    def describe(self) -> str:
        proto = self.protocol or "any"
        return (
            "%s src=%s dst=%s %s sport=%d-%d dport=%d-%d"
            % (
                self.direction,
                self.src,
                self.dst,
                proto,
                self.src_ports[0],
                self.src_ports[1],
                self.dst_ports[0],
                self.dst_ports[1],
            )
        )


@dataclass(frozen=True)
class Policy:
    """An SPD entry.  Higher ``priority`` wins; equal priority with
    different actions is reported as a conflict."""

    policy_id: str
    priority: int
    action: str  # bypass / protect / discard
    selector: Selector
    tunnel_id: Optional[str] = None  # required tunnel for protect


@dataclass(frozen=True)
class SecurityAssociation:
    """A SAD entry."""

    spi: int
    tunnel_id: str
    selector: Selector
    valid_from: float  # epoch seconds, inclusive
    valid_to: float  # epoch seconds, exclusive
    encap: str = "esp"  # "esp" or "udp" (UDP-4500 NAT-T encapsulation)
    direction: str = DIRECTION_OUTBOUND

    def is_live(self, now: float) -> bool:
        return self.valid_from <= now < self.valid_to

    @property
    def natt_capable(self) -> bool:
        return self.encap == "udp"


@dataclass(frozen=True)
class Tunnel:
    tunnel_id: str
    local_endpoint: str
    remote_endpoint: str
    interface: str
    natt_boundary: bool = False  # NAT detected between the endpoints


@dataclass(frozen=True)
class Route:
    prefix: object
    interface: str
    kind: str = "direct"  # "direct" or "tunnel"
    next_hop: Optional[str] = None  # None means connected/on-link
    tunnel_id: Optional[str] = None
    metric: int = 0

    def __post_init__(self):
        object.__setattr__(self, "prefix", _to_network(self.prefix))


@dataclass(frozen=True)
class Interface:
    name: str
    networks: Tuple[object, ...] = field(default_factory=tuple)
    up: bool = True

    def __post_init__(self):
        object.__setattr__(
            self, "networks", tuple(_to_network(n) for n in self.networks)
        )

    def covers(self, addr) -> bool:
        addr = ip_address(addr) if isinstance(addr, str) else addr
        return any(addr in net for net in self.networks)
