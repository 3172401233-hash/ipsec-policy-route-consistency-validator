import unittest

from ipsec_validator import (
    Interface,
    Policy,
    Route,
    SecurityAssociation,
    Selector,
    Tunnel,
    Validator,
)
from ipsec_validator import engine

NOW = 1_000_000.0


def make_interfaces():
    return [
        Interface("eth0", ("192.0.2.1/30",)),
        Interface("eth1", ("10.0.0.1/24",)),
        Interface("ipsec0", ()),
    ]


def make_tunnel(natt=False):
    return Tunnel(
        tunnel_id="tun1",
        local_endpoint="192.0.2.1",
        remote_endpoint="203.0.113.2",
        interface="ipsec0",
        natt_boundary=natt,
    )


def make_sa(valid_to=NOW + 3600, encap="esp", direction="outbound",
            dst="10.1.0.0/16", src="10.0.0.0/24"):
    return SecurityAssociation(
        spi=0x1001,
        tunnel_id="tun1",
        selector=Selector(src=src, dst=dst, direction=direction),
        valid_from=NOW - 100,
        valid_to=valid_to,
        encap=encap,
        direction=direction,
    )


def protect_policy(policy_id="p-protect", priority=100, direction="outbound",
                   dst="10.1.0.0/16", src="10.0.0.0/24"):
    return Policy(
        policy_id=policy_id,
        priority=priority,
        action="protect",
        selector=Selector(src=src, dst=dst, direction=direction),
        tunnel_id="tun1",
    )


def tunnel_route():
    return Route("10.1.0.0/16", "ipsec0", kind="tunnel", tunnel_id="tun1")


def direct_route():
    return Route("10.1.0.0/16", "eth0", kind="direct", next_hop="192.0.2.2")


def underlay_route():
    # reachability of the tunnel remote endpoint (203.0.113.2)
    return Route("0.0.0.0/0", "eth0", kind="direct", next_hop="192.0.2.2")


def sample(dst="10.1.0.0/16", src="10.0.0.0/24", direction="outbound"):
    return Selector(src=src, dst=dst, direction=direction)


def build_validator(policies, sas, routes, tunnels=None):
    return Validator(
        policies=policies,
        sas=sas,
        routes=routes,
        tunnels=tunnels if tunnels is not None else [make_tunnel()],
        interfaces=make_interfaces(),
    )


class PriorityTest(unittest.TestCase):
    def test_higher_priority_protect_beats_bypass(self):
        bypass = Policy(
            policy_id="p-bypass",
            priority=10,
            action="bypass",
            selector=sample(),
        )
        validator = build_validator(
            policies=[bypass, protect_policy(priority=100)],
            sas=[make_sa()],
            routes=[tunnel_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertEqual(len(verdicts), 1)
        self.assertEqual(verdicts[0].policy_action, "protect")
        self.assertEqual(verdicts[0].final_action, "protect")
        self.assertEqual(verdicts[0].sa_spi, 0x1001)

    def test_equal_priority_conflict(self):
        discard = Policy(
            policy_id="p-discard",
            priority=100,
            action="discard",
            selector=sample(),
        )
        validator = build_validator(
            policies=[discard, protect_policy(priority=100)],
            sas=[make_sa()],
            routes=[tunnel_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertEqual(verdicts[0].final_action, "conflict")
        self.assertIn(engine.F_POLICY_CONFLICT, verdicts[0].faults)


class TunnelBypassTest(unittest.TestCase):
    def test_protect_policy_but_direct_route(self):
        validator = build_validator(
            policies=[protect_policy()],
            sas=[make_sa()],
            routes=[direct_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertEqual(len(verdicts), 1)
        verdict = verdicts[0]
        self.assertEqual(verdict.policy_action, "protect")
        # traffic actually leaves unprotected
        self.assertEqual(verdict.final_action, "bypass")
        self.assertIn(engine.F_TUNNEL_BYPASS, verdict.faults)
        self.assertIn("eth0", verdict.route)

    def test_bypass_policy_with_tunnel_route_flagged(self):
        bypass = Policy(
            policy_id="p-bypass",
            priority=100,
            action="bypass",
            selector=sample(),
        )
        validator = build_validator(
            policies=[bypass],
            sas=[],
            routes=[tunnel_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertEqual(verdicts[0].final_action, "bypass")
        self.assertIn(engine.F_UNEXPECTED_TUNNEL, verdicts[0].faults)


class SymmetryTest(unittest.TestCase):
    def test_unidirectional_policy_flagged(self):
        validator = build_validator(
            policies=[protect_policy()],
            sas=[make_sa()],
            routes=[tunnel_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertIn(engine.F_ASYMMETRIC_POLICY, verdicts[0].faults)

    def test_symmetric_policies_ok(self):
        validator = build_validator(
            policies=[
                protect_policy(),
                protect_policy(
                    policy_id="p-in",
                    direction="inbound",
                    src="10.1.0.0/16",
                    dst="10.0.0.0/24",
                ),
            ],
            sas=[make_sa()],
            routes=[tunnel_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertEqual(verdicts[0].faults, [])
        self.assertEqual(verdicts[0].final_action, "protect")


class NatTraversalTest(unittest.TestCase):
    def test_natt_boundary_with_esp_only_sa(self):
        validator = build_validator(
            policies=[protect_policy()],
            sas=[make_sa(encap="esp")],
            routes=[tunnel_route(), underlay_route()],
            tunnels=[make_tunnel(natt=True)],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertIn(engine.F_NATT_MISMATCH, verdicts[0].faults)
        self.assertEqual(verdicts[0].final_action, "discard")

    def test_natt_boundary_with_udp_encap_sa_ok(self):
        validator = build_validator(
            policies=[
                protect_policy(),
                protect_policy(
                    policy_id="p-in",
                    direction="inbound",
                    src="10.1.0.0/16",
                    dst="10.0.0.0/24",
                ),
            ],
            sas=[make_sa(encap="udp")],
            routes=[tunnel_route(), underlay_route()],
            tunnels=[make_tunnel(natt=True)],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertEqual(verdicts[0].faults, [])
        self.assertEqual(verdicts[0].final_action, "protect")

    def test_natt_boundary_change_reevaluated(self):
        # Same validator instance, NAT boundary appears between calls:
        # the conclusion must change (no cached verdict).
        tunnel = make_tunnel(natt=False)
        validator = build_validator(
            policies=[protect_policy()],
            sas=[make_sa(encap="esp")],
            routes=[tunnel_route(), underlay_route()],
            tunnels=[tunnel],
        )
        before = validator.validate(sample(), NOW)
        self.assertNotIn(engine.F_NATT_MISMATCH, before[0].faults)

        validator.tunnels["tun1"] = make_tunnel(natt=True)
        after = validator.validate(sample(), NOW)
        self.assertIn(engine.F_NATT_MISMATCH, after[0].faults)


class SaLifecycleTest(unittest.TestCase):
    def test_sa_expiry_reevaluated_per_call(self):
        validator = build_validator(
            policies=[protect_policy()],
            sas=[make_sa(valid_to=NOW + 60)],
            routes=[tunnel_route(), underlay_route()],
        )
        live = validator.validate(sample(), NOW)
        self.assertEqual(live[0].final_action, "protect")
        self.assertEqual(live[0].sa_spi, 0x1001)

        expired = validator.validate(sample(), NOW + 120)
        self.assertIn(engine.F_SA_EXPIRED, expired[0].faults)
        self.assertEqual(expired[0].final_action, "discard")

    def test_deleted_sa_selector_still_hit(self):
        # Old SA removed from SAD but SPD selector still matches traffic.
        validator = build_validator(
            policies=[protect_policy()],
            sas=[],
            routes=[tunnel_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertIn(engine.F_SA_MISSING, verdicts[0].faults)
        self.assertEqual(verdicts[0].final_action, "discard")

    def test_sa_selector_narrower_than_policy(self):
        validator = build_validator(
            policies=[protect_policy()],
            sas=[make_sa(dst="10.1.0.0/24")],
            routes=[tunnel_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(dst="10.1.0.0/16"), NOW)
        narrow = [v for v in verdicts if engine.F_SA_SELECTOR_NARROW in v.faults]
        self.assertTrue(narrow)


class OverlapDecompositionTest(unittest.TestCase):
    def test_overlapping_selectors_split_ranges(self):
        # protect covers 10.1.0.0/16, discard covers 10.1.5.0/24 with
        # higher priority: the sample must be decomposed so the /24 is
        # discarded and the rest protected.
        discard = Policy(
            policy_id="p-discard-5",
            priority=200,
            action="discard",
            selector=sample(dst="10.1.5.0/24"),
        )
        validator = build_validator(
            policies=[protect_policy(), discard],
            sas=[make_sa()],
            routes=[tunnel_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertGreater(len(verdicts), 1)
        actions = {}
        for verdict in verdicts:
            actions[str(verdict.cell.dst)] = verdict.final_action
        self.assertEqual(actions["10.1.5.0/24"], "discard")
        self.assertIn("protect", actions.values())
        # sub-ranges must exactly cover the sample destination
        covered = sorted(
            (v.cell.dst.network_address, v.cell.dst.broadcast_address)
            for v in verdicts
        )
        self.assertEqual(covered[0][0], sample().dst.network_address)
        self.assertEqual(covered[-1][1], sample().dst.broadcast_address)

    def test_no_match_range(self):
        validator = build_validator(
            policies=[protect_policy(dst="10.1.0.0/24")],
            sas=[make_sa()],
            routes=[tunnel_route(), underlay_route()],
        )
        verdicts = validator.validate(sample(dst="10.1.0.0/16"), NOW)
        no_match = [v for v in verdicts if v.policy_action == "no-match"]
        protected = [v for v in verdicts if v.policy_action == "protect"]
        self.assertTrue(no_match)
        self.assertTrue(protected)


class ReachabilityTest(unittest.TestCase):
    def test_tunnel_endpoint_unreachable(self):
        validator = build_validator(
            policies=[protect_policy()],
            sas=[make_sa()],
            routes=[tunnel_route()],  # no underlay route to 192.0.2.2
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertIn(engine.F_TUNNEL_ENDPOINT_UNREACHABLE, verdicts[0].faults)
        self.assertEqual(verdicts[0].final_action, "discard")

    def test_interface_down(self):
        validator = Validator(
            policies=[protect_policy()],
            sas=[make_sa()],
            routes=[tunnel_route(), underlay_route()],
            tunnels=[make_tunnel()],
            interfaces=[
                Interface("eth0", ("192.0.2.1/30",), up=False),
                Interface("ipsec0", ()),
            ],
        )
        verdicts = validator.validate(sample(), NOW)
        self.assertIn(engine.F_TUNNEL_ENDPOINT_UNREACHABLE, verdicts[0].faults)


if __name__ == "__main__":
    unittest.main()
