import copy, unittest
from certchain import *

def setup():
    reg, uni, other = Wallet(), Wallet(), Wallet()
    node = Node("A", reg.address)
    node.submit(reg.tx("ADD_INSTITUTION", {"address": uni.address, "name": "VESIT"}))
    node.mine_block()
    return reg, uni, other, node

def cert(i=1, salt="s1"):
    return {"student": f"Student {i}", "id": f"MCA{i:03d}", "programme": "MCA",
            "grade": "A", "year": 2027, "institution": "VESIT", "salt": salt}

class TestLedger(unittest.TestCase):
    def test_mining_and_validation(self):
        reg, uni, o, node = setup()
        node.submit(uni.tx("ISSUE_CERT", {"cert_hash": certificate_hash(cert())}))
        b = node.mine_block()
        self.assertTrue(b.hash.startswith("0" * DIFFICULTY))
        self.assertTrue(validate_chain(node.chain, reg.address)[0])

    def test_tampering_is_detected(self):
        reg, uni, o, node = setup()
        node.submit(uni.tx("ISSUE_CERT", {"cert_hash": certificate_hash(cert())}))
        node.mine_block()
        bad = copy.deepcopy(node.chain)
        bad[2].txs[0].payload["cert_hash"] = "00" * 32
        self.assertFalse(validate_chain(bad, reg.address)[0])

    def test_forged_signature_rejected(self):
        reg, uni, o, node = setup()
        t = o.tx("ISSUE_CERT", {"cert_hash": "ab"})
        t.sender_pub, t.sender = uni.pub_hex, uni.address   # attacker claims to be the university
        with self.assertRaises(RuleError): node.submit(t)

    def test_rewriting_history_breaks_links(self):
        reg, uni, o, node = setup()
        node.submit(uni.tx("ISSUE_CERT", {"cert_hash": certificate_hash(cert())}))
        node.mine_block()
        bad = copy.deepcopy(node.chain)
        bad[1].timestamp += 1
        ok, msg, _ = validate_chain(bad, reg.address)
        self.assertFalse(ok)

    def test_longest_chain_rule(self):
        reg, uni, o, a = setup()
        b = Node("B", reg.address)
        self.assertTrue(b.replace_chain(copy.deepcopy(a.chain)))
        a.submit(uni.tx("ISSUE_CERT", {"cert_hash": certificate_hash(cert())}))
        a.mine_block(gossip=False)
        self.assertEqual((a.height(), b.height()), (3, 2))
        self.assertTrue(b.replace_chain(copy.deepcopy(a.chain)))
        self.assertEqual(b.height(), 3)

class TestRules(unittest.TestCase):
    def test_only_regulator_adds_institution(self):
        reg, uni, o, node = setup()
        with self.assertRaises(RuleError):
            node.submit(o.tx("ADD_INSTITUTION", {"address": o.address, "name": "FakeU"}))

    def test_unapproved_institution_cannot_issue(self):
        reg, uni, o, node = setup()
        with self.assertRaises(RuleError):
            node.submit(o.tx("ISSUE_CERT", {"cert_hash": "ab"}))

    def test_duplicate_certificate_rejected(self):
        reg, uni, o, node = setup()
        h = certificate_hash(cert())
        node.submit(uni.tx("ISSUE_CERT", {"cert_hash": h})); node.mine_block()
        with self.assertRaises(RuleError):
            node.submit(uni.tx("ISSUE_CERT", {"cert_hash": h}))

    def test_only_issuer_can_revoke(self):
        reg, uni, o, node = setup()
        h = certificate_hash(cert())
        node.submit(uni.tx("ISSUE_CERT", {"cert_hash": h})); node.mine_block()
        with self.assertRaises(RuleError):
            node.submit(reg.tx("REVOKE_CERT", {"cert_hash": h, "reason": "x"}))

    def test_replay_protection(self):
        reg, uni, o, node = setup()
        t = uni.tx("ISSUE_CERT", {"cert_hash": certificate_hash(cert())})
        node.submit(t); node.mine_block()
        with self.assertRaises(RuleError): node.submit(Transaction.from_dict(t.to_dict()))

    def test_verify_genuine_and_revoked(self):
        reg, uni, o, node = setup()
        c = cert(); h = certificate_hash(c)
        node.submit(uni.tx("ISSUE_CERT", {"cert_hash": h})); node.mine_block()
        self.assertEqual(verify_certificate(node, c)[0], "VALID")
        node.submit(uni.tx("REVOKE_CERT", {"cert_hash": h, "reason": "degree withdrawn"})); node.mine_block()
        self.assertEqual(verify_certificate(node, c)[0], "REVOKED")

    def test_verify_forged_certificate(self):
        reg, uni, o, node = setup()
        c = cert()
        node.submit(uni.tx("ISSUE_CERT", {"cert_hash": certificate_hash(c)})); node.mine_block()
        forged = dict(c, grade="A+")
        self.assertEqual(verify_certificate(node, forged)[0], "NOT FOUND")

if __name__ == "__main__":
    unittest.main()
