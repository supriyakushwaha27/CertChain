import copy
from certchain import *
reg, uni, rogue = Wallet(), Wallet(), Wallet()
A, B = Node("Node-A", reg.address), Node("Node-B", reg.address)
A.peers, B.peers = [B], [A]
print("Regulator address :", reg.address)
print("Genesis block hash:", A.chain[0].hash)
A.submit(reg.tx("ADD_INSTITUTION", {"address": uni.address, "name": "VESIT"})); A.mine_block()
print("Institution registered: VESIT", uni.address)
certs = [{"student": n, "id": i, "programme": "MCA", "grade": g, "year": 2027,
          "institution": "VESIT", "salt": f"salt{k}"}
         for k, (n, i, g) in enumerate([("Aria Shah","MCA101","A"),("Kael Rao","MCA102","B+"),("Mira Nair","MCA103","A+")])]
for c in certs:
    A.submit(uni.tx("ISSUE_CERT", {"cert_hash": certificate_hash(c)}))
print("Pending on Node-B (gossiped from A):", len(B.mempool))
b = B.mine_block()      # mined on B, accepted by A
print(f"Block {b.index} mined on Node-B: hash={b.hash[:16]}... txs={len(b.txs)} merkle={b.merkle[:16]}...")
print("Heights  A:", A.height(), " B:", B.height())
print()
for label, c in [("genuine", certs[0]), ("forged grade", dict(certs[1], grade="A+")), ("unknown student", dict(certs[2], id="MCA999"))]:
    print(f"verify [{label:15}] ->", *verify_certificate(A, c))
for lab, w, act, p in [("rogue institution issues", rogue, "ISSUE_CERT", {"cert_hash": "ab"*32}),
                       ("rogue adds itself", rogue, "ADD_INSTITUTION", {"address": rogue.address, "name": "FakeU"})]:
    w.nonce = 0
    try: A.submit(w.tx(act, p))
    except RuleError as e: print(f"rejected by smart contract ({lab}): {e}")
h = certificate_hash(certs[2])
A.submit(uni.tx("REVOKE_CERT", {"cert_hash": h, "reason": "degree withdrawn"})); A.mine_block()
print("verify [after revocation ] ->", *verify_certificate(B, certs[2]))
print()
print("Validate real chain :", validate_chain(A.chain, reg.address)[:2])
bad = copy.deepcopy(A.chain); bad[2].txs[1].payload["cert_hash"] = "ff"*32
print("Validate tampered   :", validate_chain(bad, reg.address)[:2])
