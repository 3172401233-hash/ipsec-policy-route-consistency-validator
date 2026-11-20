"""Prefix and port-range splitting helpers used to decompose a traffic
sample into sub-ranges on which the policy/route decision is uniform."""

from typing import List, Tuple


def split_network(net, cuts) -> List:
    """Split ``net`` into disjoint subnets such that every network in
    ``cuts`` either fully contains or is disjoint from each piece."""
    pieces = [net]
    for cut in cuts:
        if cut.version != net.version:
            continue
        refined = []
        for piece in pieces:
            if not piece.overlaps(cut) or piece.subnet_of(cut):
                refined.append(piece)
            else:
                # For prefixes, overlap without containment implies the
                # cut is strictly inside the piece.
                refined.append(cut)
                refined.extend(piece.address_exclude(cut))
        pieces = refined
    return pieces


def split_port_range(
    lo: int, hi: int, cuts: List[Tuple[int, int]]
) -> List[Tuple[int, int]]:
    """Split [lo, hi] into maximal sub-ranges uniform w.r.t. ``cuts``."""
    bounds = {lo, hi + 1}
    for c_lo, c_hi in cuts:
        if c_hi < lo or c_lo > hi:
            continue
        bounds.add(max(c_lo, lo))
        bounds.add(min(c_hi + 1, hi + 1))
    points = sorted(bounds)
    return [(a, b - 1) for a, b in zip(points, points[1:])]
