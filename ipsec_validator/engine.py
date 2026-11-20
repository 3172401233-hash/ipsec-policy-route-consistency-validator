"""Consistency validation engine.

The engine is deliberately stateless: every call to :meth:`Validator.validate`
re-evaluates SPD, SAD, routing and NAT-T state at the supplied ``now``
timestamp.  No verdict is ever cached, so an SA expiring or a NAT boundary
appearing/disappearing automatically changes the next result.
"""

from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Dict, List, Optional, Tuple

from .model import (
    ACTION_BYPASS,
    ACTION_CONFLICT,
    ACTION_DISCARD,
    ACTION_NO_MATCH,
    ACTION_PROTECT,
    DIRECTION_INBOUND,
    DIRECTION_OUTBOUND,
    Interface,
    Policy,
    Route,
    SecurityAssociation,
    Selector,
    Tunnel,
)
from .prefix import split_network, split_port_range

# Fault codes
F_POLICY_CONFLICT = "POLICY_CONFLICT"
F_SA_MISSING = "SA_MISSING"
F_SA_EXPIRED = "SA_EXPIRED"
F_SA_SELECTOR_NARROW = "SA_SELECTOR_NARROW"
F_TUNNEL_BYPASS = "TUNNEL_BYPASS"
F_UNEXPECTED_TUNNEL = "UNEXPECTED_TUNNEL"
F_TUNNEL_ENDPOINT_UNREACHABLE = "TUNNEL_ENDPOINT_UNREACHABLE"
F_NH_UNREACHABLE = "NEXT_HOP_UNREACHABLE"
F_INTERFACE_DOWN = "INTERFACE_DOWN"
F_NATT_MISMATCH = "NATT_MISMATCH"
F_ASYMMETRIC_POLICY = "ASYMMETRIC_POLICY"

_MAX_NH_DEPTH = 8


@dataclass
class Verdict:
    """Result for one uniform traffic sub-range."""

    cell: Selector
    policy_action: str  # action selected from the SPD (or no-match/conflict)
    final_action: str  # what actually happens to the traffic
    policy_id: Optional[str] = None
    sa_spi: Optional[int] = None
    route: Optional[str] = None  # human-readable route evidence
    faults: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.faults


def _ports_cover(outer: Tuple[int, int], inner: Tuple[int, int]) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def selector_covers(outer: Selector, inner: Selector) -> bool:
    """True if ``outer`` fully covers ``inner`` (direction included)."""
    if outer.direction != inner.direction:
        return False
    if outer.src.version != inner.src.version or outer.dst.version != inner.dst.version:
        return False
    if not inner.src.subnet_of(outer.src):
        return False
    if not inner.dst.subnet_of(outer.dst):
        return False
    if not _ports_cover(outer.src_ports, inner.src_ports):
        return False
    if not _ports_cover(outer.dst_ports, inner.dst_ports):
        return False
    if outer.protocol is not None and outer.protocol != inner.protocol:
        return False
    return True


class Validator:
    """Offline, read-only consistency checker."""

    def __init__(
        self,
        policies: List[Policy],
        sas: List[SecurityAssociation],
        routes: List[Route],
        tunnels: List[Tunnel],
        interfaces: List[Interface],
    ):
        self.policies = list(policies)
        self.sas = list(sas)
        self.routes = list(routes)
        self.tunnels: Dict[str, Tunnel] = {t.tunnel_id: t for t in tunnels}
        self.interfaces: Dict[str, Interface] = {i.name: i for i in interfaces}

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def validate(self, sample: Selector, now: float) -> List[Verdict]:
        """Evaluate ``sample`` at time ``now``.

        Returns one :class:`Verdict` per uniform sub-range of the sample.
        Nothing is cached between calls: SA lifetimes and NAT-T state are
        re-read on every invocation.
        """
        verdicts = []
        for cell in self._decompose(sample):
            verdicts.append(self._evaluate_cell(cell, now))
        return verdicts

    # ------------------------------------------------------------------
    # decomposition
    # ------------------------------------------------------------------
    def _decompose(self, sample: Selector) -> List[Selector]:
        direction_policies = [
            p for p in self.policies if p.selector.direction == sample.direction
        ]
        src_cuts = [p.selector.src for p in direction_policies]
        dst_cuts = [p.selector.dst for p in direction_policies]
        # Route boundaries also matter: the forwarding decision must be
        # uniform inside each cell.
        dst_cuts += [r.prefix for r in self.routes]
        sport_cuts = [p.selector.src_ports for p in direction_policies]
        dport_cuts = [p.selector.dst_ports for p in direction_policies]

        src_pieces = split_network(sample.src, src_cuts)
        dst_pieces = split_network(sample.dst, dst_cuts)
        sport_pieces = split_port_range(sample.src_ports[0], sample.src_ports[1], sport_cuts)
        dport_pieces = split_port_range(sample.dst_ports[0], sample.dst_ports[1], dport_cuts)

        cells = []
        for src in src_pieces:
            for dst in dst_pieces:
                for sport in sport_pieces:
                    for dport in dport_pieces:
                        cells.append(
                            Selector(
                                src=src,
                                dst=dst,
                                protocol=sample.protocol,
                                src_ports=sport,
                                dst_ports=dport,
                                direction=sample.direction,
                            )
                        )
        return cells

    # ------------------------------------------------------------------
    # per-cell evaluation
    # ------------------------------------------------------------------
    def _evaluate_cell(self, cell: Selector, now: float) -> Verdict:
        matches = [p for p in self.policies if selector_covers(p.selector, cell)]
        route, route_faults, route_desc = self._route_evidence(cell)

        if not matches:
            return Verdict(
                cell=cell,
                policy_action=ACTION_NO_MATCH,
                final_action=ACTION_NO_MATCH,
                route=route_desc,
                faults=route_faults,
                notes=["no SPD entry covers this range"],
            )

        best_priority = max(p.priority for p in matches)
        tops = [p for p in matches if p.priority == best_priority]
        actions = {p.action for p in tops}
        if len(actions) > 1:
            return Verdict(
                cell=cell,
                policy_action=ACTION_CONFLICT,
                final_action=ACTION_CONFLICT,
                route=route_desc,
                faults=[F_POLICY_CONFLICT] + route_faults,
                notes=[
                    "equal-priority policies disagree: "
                    + ", ".join(
                        "%s(%s)" % (p.policy_id, p.action) for p in tops
                    )
                ],
            )

        policy = tops[0]
        if policy.action == ACTION_DISCARD:
            return Verdict(
                cell=cell,
                policy_action=ACTION_DISCARD,
                final_action=ACTION_DISCARD,
                policy_id=policy.policy_id,
                route=route_desc,
                faults=route_faults,
            )
        if policy.action == ACTION_BYPASS:
            return self._evaluate_bypass(cell, policy, route, route_faults, route_desc)
        return self._evaluate_protect(cell, policy, now, route, route_faults, route_desc)

    def _evaluate_bypass(self, cell, policy, route, route_faults, route_desc) -> Verdict:
        faults = list(route_faults)
        if route is not None and route.kind == "tunnel":
            faults.append(F_UNEXPECTED_TUNNEL)
        return Verdict(
            cell=cell,
            policy_action=ACTION_BYPASS,
            final_action=ACTION_BYPASS,
            policy_id=policy.policy_id,
            route=route_desc,
            faults=faults,
        )

    def _evaluate_protect(self, cell, policy, now, route, route_faults, route_desc) -> Verdict:
        faults = list(route_faults)
        notes = []

        # --- SAD lookup: SA must fully cover the cell ---
        sa, sa_fault, sa_note = self._find_sa(cell, policy, now)
        if sa_fault:
            faults.append(sa_fault)
        if sa_note:
            notes.append(sa_note)

        # --- route vs. policy consistency ---
        route_bypasses = False
        if route is None:
            faults.append(F_NH_UNREACHABLE)
            notes.append("no route for destination")
        elif route.kind != "tunnel" or (
            policy.tunnel_id and route.tunnel_id != policy.tunnel_id
        ):
            route_bypasses = True
            faults.append(F_TUNNEL_BYPASS)
            notes.append("policy requires encryption but route leaves the tunnel")
        else:
            tunnel = self.tunnels.get(route.tunnel_id)
            if tunnel is None:
                faults.append(F_TUNNEL_ENDPOINT_UNREACHABLE)
            else:
                if not self._reachable(ip_address(tunnel.remote_endpoint)):
                    faults.append(F_TUNNEL_ENDPOINT_UNREACHABLE)
                    notes.append(
                        "tunnel remote endpoint %s is unreachable"
                        % tunnel.remote_endpoint
                    )
                if tunnel.natt_boundary and sa is not None and not sa.natt_capable:
                    faults.append(F_NATT_MISMATCH)
                    notes.append(
                        "NAT boundary on path but SA 0x%08x uses plain ESP" % sa.spi
                    )

        # --- inbound/outbound symmetry ---
        if not self._has_mirror_policy(cell):
            faults.append(F_ASYMMETRIC_POLICY)
            notes.append("no mirrored %s protect policy" % (
                DIRECTION_INBOUND
                if cell.direction == DIRECTION_OUTBOUND
                else DIRECTION_OUTBOUND
            ))

        # --- effective action ---
        if route_bypasses:
            final = ACTION_BYPASS  # traffic actually leaves unprotected
        elif faults and any(
            f in faults
            for f in (
                F_SA_MISSING,
                F_SA_EXPIRED,
                F_SA_SELECTOR_NARROW,
                F_NATT_MISMATCH,
                F_TUNNEL_ENDPOINT_UNREACHABLE,
                F_NH_UNREACHABLE,
                F_INTERFACE_DOWN,
            )
        ):
            final = ACTION_DISCARD  # protected traffic with no usable path/SA
        else:
            final = ACTION_PROTECT

        return Verdict(
            cell=cell,
            policy_action=ACTION_PROTECT,
            final_action=final,
            policy_id=policy.policy_id,
            sa_spi=sa.spi if sa is not None else None,
            route=route_desc,
            faults=faults,
            notes=notes,
        )

    # ------------------------------------------------------------------
    # SAD
    # ------------------------------------------------------------------
    def _find_sa(self, cell, policy, now):
        """Return (sa, fault, note).  SA liveness is checked against ``now``
        on every call; expired SAs are never reused from a prior verdict."""
        candidates = [
            s
            for s in self.sas
            if s.direction == cell.direction
            and (policy.tunnel_id is None or s.tunnel_id == policy.tunnel_id)
        ]
        covering = []
        partial = False
        for sa in candidates:
            if selector_covers(sa.selector, cell):
                covering.append(sa)
            elif self._selectors_overlap(sa.selector, cell):
                partial = True
        if not covering:
            if partial:
                return None, F_SA_SELECTOR_NARROW, (
                    "existing SA selector only partially covers this range"
                )
            return None, F_SA_MISSING, "no SA covers this range"
        live = [s for s in covering if s.is_live(now)]
        if not live:
            latest = max(covering, key=lambda s: s.valid_to)
            return latest, F_SA_EXPIRED, (
                "SA 0x%08x expired at %.0f (now=%.0f)"
                % (latest.spi, latest.valid_to, now)
            )
        return live[0], None, None

    @staticmethod
    def _selectors_overlap(a: Selector, b: Selector) -> bool:
        if a.direction != b.direction:
            return False
        if a.src.version != b.src.version or a.dst.version != b.dst.version:
            return False
        if not (a.src.overlaps(b.src) and a.dst.overlaps(b.dst)):
            return False
        if a.protocol is not None and b.protocol is not None and a.protocol != b.protocol:
            return False
        for pa, pb in ((a.src_ports, b.src_ports), (a.dst_ports, b.dst_ports)):
            if pa[1] < pb[0] or pb[1] < pa[0]:
                return False
        return True

    # ------------------------------------------------------------------
    # routing
    # ------------------------------------------------------------------
    def _route_evidence(self, cell):
        """Return (route, faults, description) for the cell's destination."""
        addr = cell.dst.network_address
        route = self._lookup_route(addr)
        if route is None:
            return None, [F_NH_UNREACHABLE], "no route to %s" % cell.dst
        faults = []
        iface = self.interfaces.get(route.interface)
        if iface is None or not iface.up:
            faults.append(F_INTERFACE_DOWN)
        nh = route.next_hop or "connected"
        desc = "dst %s via %s dev %s (%s" % (
            cell.dst,
            route.prefix,
            route.interface,
            route.kind,
        )
        if route.tunnel_id:
            desc += ", tunnel=%s" % route.tunnel_id
        desc += ", nh=%s)" % nh
        if route.next_hop is not None and not self._reachable(ip_address(route.next_hop)):
            faults.append(F_NH_UNREACHABLE)
        return route, faults, desc

    def _lookup_route(self, addr) -> Optional[Route]:
        best = None
        for route in self.routes:
            if route.prefix.version != addr.version:
                continue
            if addr not in route.prefix:
                continue
            if (
                best is None
                or route.prefix.prefixlen > best.prefix.prefixlen
                or (
                    route.prefix.prefixlen == best.prefix.prefixlen
                    and route.metric < best.metric
                )
            ):
                best = route
        return best

    def _reachable(self, addr, depth: int = 0) -> bool:
        if depth > _MAX_NH_DEPTH:
            return False
        for iface in self.interfaces.values():
            if iface.up and iface.covers(addr):
                return True
        route = self._lookup_route(addr)
        if route is None:
            return False
        iface = self.interfaces.get(route.interface)
        if iface is None or not iface.up:
            return False
        if route.next_hop is None:
            return True
        return self._reachable(ip_address(route.next_hop), depth + 1)

    # ------------------------------------------------------------------
    # symmetry
    # ------------------------------------------------------------------
    def _has_mirror_policy(self, cell) -> bool:
        mirror = cell.mirrored()
        for policy in self.policies:
            if policy.action != ACTION_PROTECT:
                continue
            if selector_covers(policy.selector, mirror):
                return True
        return False
