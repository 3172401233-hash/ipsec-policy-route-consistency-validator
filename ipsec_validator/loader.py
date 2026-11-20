"""Build validator inputs from plain dicts (e.g. parsed JSON)."""

from typing import List

from .model import (
    Interface,
    Policy,
    Route,
    SecurityAssociation,
    Selector,
    Tunnel,
)


def _selector(data) -> Selector:
    return Selector(
        src=data["src"],
        dst=data["dst"],
        protocol=data.get("protocol"),
        src_ports=tuple(data.get("src_ports", (0, 65535))),
        dst_ports=tuple(data.get("dst_ports", (0, 65535))),
        direction=data.get("direction", "outbound"),
    )


def load_policies(items) -> List[Policy]:
    return [
        Policy(
            policy_id=item["id"],
            priority=item["priority"],
            action=item["action"],
            selector=_selector(item["selector"]),
            tunnel_id=item.get("tunnel_id"),
        )
        for item in items
    ]


def load_sas(items) -> List[SecurityAssociation]:
    return [
        SecurityAssociation(
            spi=int(item["spi"], 0) if isinstance(item["spi"], str) else item["spi"],
            tunnel_id=item["tunnel_id"],
            selector=_selector(item["selector"]),
            valid_from=item["valid_from"],
            valid_to=item["valid_to"],
            encap=item.get("encap", "esp"),
            direction=item.get("direction", "outbound"),
        )
        for item in items
    ]


def load_routes(items) -> List[Route]:
    return [
        Route(
            prefix=item["prefix"],
            interface=item["interface"],
            kind=item.get("kind", "direct"),
            next_hop=item.get("next_hop"),
            tunnel_id=item.get("tunnel_id"),
            metric=item.get("metric", 0),
        )
        for item in items
    ]


def load_tunnels(items) -> List[Tunnel]:
    return [
        Tunnel(
            tunnel_id=item["id"],
            local_endpoint=item["local_endpoint"],
            remote_endpoint=item["remote_endpoint"],
            interface=item["interface"],
            natt_boundary=item.get("natt_boundary", False),
        )
        for item in items
    ]


def load_interfaces(items) -> List[Interface]:
    return [
        Interface(
            name=item["name"],
            networks=tuple(item.get("networks", ())),
            up=item.get("up", True),
        )
        for item in items
    ]


def load_sample(data) -> Selector:
    return _selector(data)
