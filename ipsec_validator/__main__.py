"""Command-line entry point.

Usage:
    python -m ipsec_validator scenario.json

The scenario JSON has keys: now, sample, policies, sas, routes, tunnels,
interfaces.  The tool is offline and read-only; it never modifies any
system IPsec or routing state.
"""

import json
import sys

from .engine import Validator
from .loader import (
    load_interfaces,
    load_policies,
    load_routes,
    load_sample,
    load_sas,
    load_tunnels,
)
from .report import format_verdicts


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write("usage: python -m ipsec_validator scenario.json\n")
        return 2
    with open(argv[0], "r", encoding="utf-8") as handle:
        scenario = json.load(handle)

    validator = Validator(
        policies=load_policies(scenario.get("policies", [])),
        sas=load_sas(scenario.get("sas", [])),
        routes=load_routes(scenario.get("routes", [])),
        tunnels=load_tunnels(scenario.get("tunnels", [])),
        interfaces=load_interfaces(scenario.get("interfaces", [])),
    )
    now = float(scenario["now"])
    verdicts = validator.validate(load_sample(scenario["sample"]), now)
    print(format_verdicts(verdicts, now))
    return 1 if any(not v.ok for v in verdicts) else 0


if __name__ == "__main__":
    sys.exit(main())
