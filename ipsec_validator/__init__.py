"""Offline IPsec SPD/SAD/route consistency validator.

This package is strictly read-only: it never touches system IPsec
configuration.  All inputs (SPD policies, SAD entries, routes, tunnels,
interfaces, NAT-T state) are supplied by the caller as plain data.
"""

from .model import (
    Selector,
    Policy,
    SecurityAssociation,
    Tunnel,
    Route,
    Interface,
)
from .engine import Validator, Verdict

__all__ = [
    "Selector",
    "Policy",
    "SecurityAssociation",
    "Tunnel",
    "Route",
    "Interface",
    "Validator",
    "Verdict",
]
