import time, copy, random, statistics
from certchain import *
random.seed(7)
reg, uni = Wallet(), Wallet()
n = Node("A", reg.address)
n.submit(reg.tx("ADD_INSTITUTION", {"address": uni.address, "name": "VESIT"})); n.mine_block()
N, BATCH = 500, 50
certs = [{"student": f"S{i}", "id": f"MCA{i:04d}", "programme": "MCA", "grade": random.choice(["A+","A","B+","B"]),
          "year": 2027, "institution": "VESIT", "salt": f"{random.getrandbits(64):x}"} for i in range(N)]
t0 = time.perf_counter(); mt = []
for s in range(0, N, BATCH):
    for c in certs[s:s+BATCH]: n.submit(uni.tx("ISSUE_CERT", {"cert_hash": certificate_hash(c)}))
    t1 = time.perf_counter(); n.mine_block(); mt.append(time.perf_counter()-t1)
total = time.perf_counter()-t0
print(f"Issued {N} certificates in {n.height()-2} blocks of {BATCH}: {total:.1f}s total ({N/total:.1f} certs/s incl. mining)")
print(f"Avg block mining time (difficulty {DIFFICULTY}): {statistics.mean(mt):.2f}s")
tam = random.sample(range(N), 100)
forged = [dict(certs[i], grade="A+" if certs[i]["grade"]!="A+" else "A") for i in tam]
t = time.perf_counter()
ok = sum(verify_certificate(n, c)[0]=="VALID" for c in certs)
det = sum(verify_certificate(n, c)[0]=="NOT FOUND" for c in forged)
vt = (time.perf_counter()-t)/(N+len(forged))
print(f"Genuine accepted: {ok}/{N}   Forged detected: {det}/{len(forged)}   Avg verification: {vt*1e6:.0f} microseconds")
t = time.perf_counter(); ok_, msg, _ = validate_chain(n.chain, reg.address); print(f"Full-chain re-validation ({n.height()} blocks, {N+1} txs): {time.perf_counter()-t:.2f}s -> {ok_}")
tx_bytes = len(canonical(n.chain[2].txs[0].to_dict()))
print(f"On-chain size per certificate: ~{tx_bytes} bytes (hash only; no personal data stored)")
