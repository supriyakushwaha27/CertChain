"""CertChain - blockchain-based academic certificate issuance and verification.

Purpose-built proof-of-work chain: ECDSA (secp256k1) wallets, signed transactions,
Merkle-tree blocks, a deterministic rule engine (LedgerState) acting as the
"smart contract", longest-valid-chain consensus and in-process peer nodes.
"""
import copy
import hashlib
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

DIFFICULTY = 4  # leading zero hex digits required in a block hash


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def address_of(pub_hex: str) -> str:
    return "0x" + sha256(bytes.fromhex(pub_hex))[:40]


class Wallet:
    def __init__(self):
        self._priv = ec.generate_private_key(ec.SECP256K1())
        pub = self._priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.pub_hex = pub.hex()
        self.address = address_of(self.pub_hex)
        self.nonce = 0

    def sign(self, message: bytes) -> str:
        return self._priv.sign(message, ec.ECDSA(hashes.SHA256())).hex()

    def tx(self, action: str, payload: dict, nonce=None) -> "Transaction":
        t = Transaction(self.pub_hex, action, payload,
                        self.nonce if nonce is None else nonce)
        t.signature = self.sign(t.body_bytes())
        t.tx_id = t.compute_id()
        if nonce is None:
            self.nonce += 1
        return t


def verify_signature(pub_hex: str, message: bytes, sig_hex: str) -> bool:
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


class Transaction:
    def __init__(self, sender_pub, action, payload, nonce, timestamp=None):
        self.sender_pub = sender_pub
        self.sender = address_of(sender_pub)
        self.action = action
        self.payload = payload
        self.nonce = nonce
        self.timestamp = timestamp if timestamp is not None else int(time.time())
        self.signature = ""
        self.tx_id = ""

    def body(self):
        return {"sender_pub": self.sender_pub, "action": self.action,
                "payload": self.payload, "nonce": self.nonce,
                "timestamp": self.timestamp}

    def body_bytes(self):
        return canonical(self.body())

    def compute_id(self):
        return sha256(self.body_bytes() + self.signature.encode())

    def to_dict(self):
        d = self.body()
        d.update(signature=self.signature, tx_id=self.tx_id)
        return d

    @staticmethod
    def from_dict(d):
        t = Transaction(d["sender_pub"], d["action"], d["payload"], d["nonce"], d["timestamp"])
        t.signature, t.tx_id = d["signature"], d["tx_id"]
        return t


class RuleError(Exception):
    pass


class LedgerState:
    """Deterministic rule engine executed by every node for every transaction."""

    def __init__(self, regulator_address):
        self.regulator = regulator_address
        self.institutions = {}   # address -> {"name": str, "active": bool}
        self.certs = {}          # cert_id -> record
        self.nonces = {}         # address -> next expected nonce

    def apply(self, tx: Transaction):
        if not verify_signature(tx.sender_pub, tx.body_bytes(), tx.signature):
            raise RuleError("invalid signature")
        if tx.tx_id != tx.compute_id():
            raise RuleError("bad transaction id")
        if self.nonces.get(tx.sender, 0) != tx.nonce:
            raise RuleError("wrong nonce (replay or out-of-order)")
        getattr(self, "_" + tx.action.lower(), self._unknown)(tx)
        self.nonces[tx.sender] = tx.nonce + 1

    def _unknown(self, tx):
        raise RuleError("unknown action " + tx.action)

    def _add_institution(self, tx):
        if tx.sender != self.regulator:
            raise RuleError("only the regulator can add institutions")
        p = tx.payload
        self.institutions[p["address"]] = {"name": p["name"], "active": True}

    def _remove_institution(self, tx):
        if tx.sender != self.regulator:
            raise RuleError("only the regulator can remove institutions")
        if tx.payload["address"] not in self.institutions:
            raise RuleError("institution not registered")
        self.institutions[tx.payload["address"]]["active"] = False

    def _issue_cert(self, tx):
        inst = self.institutions.get(tx.sender)
        if not inst or not inst["active"]:
            raise RuleError("sender is not an approved institution")
        p = tx.payload
        if p["cert_hash"] in self.certs:
            raise RuleError("certificate already registered")
        self.certs[p["cert_hash"]] = {
            "issuer": tx.sender, "issuer_name": inst["name"],
            "issued_at": tx.timestamp, "revoked": False,
            "revoke_reason": None, "issue_tx": tx.tx_id, "revoke_tx": None}

    def _revoke_cert(self, tx):
        rec = self.certs.get(tx.payload["cert_hash"])
        if rec is None:
            raise RuleError("certificate not found")
        if rec["issuer"] != tx.sender:
            raise RuleError("only the issuing institution can revoke")
        if rec["revoked"]:
            raise RuleError("already revoked")
        rec.update(revoked=True, revoke_reason=tx.payload.get("reason", ""),
                   revoke_tx=tx.tx_id)


def merkle_root(tx_ids):
    if not tx_ids:
        return sha256(b"")
    level = list(tx_ids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256((level[i] + level[i + 1]).encode()) for i in range(0, len(level), 2)]
    return level[0]


class Block:
    def __init__(self, index, prev_hash, txs, timestamp=None, nonce=0):
        self.index, self.prev_hash, self.txs = index, prev_hash, txs
        self.timestamp = timestamp if timestamp is not None else int(time.time())
        self.nonce = nonce
        self.merkle = merkle_root([t.tx_id for t in txs])
        self.hash = self.compute_hash()

    def header(self):
        return canonical({"index": self.index, "prev_hash": self.prev_hash,
                          "merkle": self.merkle, "timestamp": self.timestamp,
                          "difficulty": DIFFICULTY, "nonce": self.nonce})

    def compute_hash(self):
        return sha256(self.header())

    def mine(self):
        while True:
            self.hash = self.compute_hash()
            if self.hash.startswith("0" * DIFFICULTY):
                return self
            self.nonce += 1

    def to_dict(self):
        return {"index": self.index, "prev_hash": self.prev_hash,
                "timestamp": self.timestamp, "nonce": self.nonce,
                "merkle": self.merkle, "hash": self.hash,
                "txs": [t.to_dict() for t in self.txs]}

    @staticmethod
    def from_dict(d):
        b = Block(d["index"], d["prev_hash"], [Transaction.from_dict(t) for t in d["txs"]],
                  d["timestamp"], d["nonce"])
        b.hash = d["hash"]
        b.merkle = d["merkle"]  # kept as claimed; validation recomputes it
        return b


def validate_chain(chain, regulator_address):
    """Replay every block from genesis. Returns (ok, message, final_state)."""
    state = LedgerState(regulator_address)
    for i, b in enumerate(chain):
        if b.index != i:
            return False, f"block {i}: bad index", None
        if i > 0 and b.prev_hash != chain[i - 1].hash:
            return False, f"block {i}: broken link to previous hash", None
        if b.merkle != merkle_root([t.tx_id for t in b.txs]):
            return False, f"block {i}: Merkle root mismatch", None
        if b.hash != b.compute_hash():
            return False, f"block {i}: hash mismatch", None
        if not b.hash.startswith("0" * DIFFICULTY):
            return False, f"block {i}: proof-of-work not satisfied", None
        for t in b.txs:
            try:
                state.apply(t)
            except RuleError as e:
                return False, f"block {i}, tx {t.tx_id[:8]}...: {e}", None
    return True, f"chain valid: {len(chain)} blocks, all hashes, Merkle roots, signatures and rules verified", state


class Node:
    def __init__(self, name, regulator_address):
        self.name, self.regulator = name, regulator_address
        genesis = Block(0, "0" * 64, [], timestamp=0).mine()
        self.chain = [genesis]
        self.mempool = []
        self.state = LedgerState(regulator_address)
        self.peers = []

    def height(self):
        return len(self.chain)

    def submit(self, tx, gossip=True):
        trial = copy.deepcopy(self.state)  # pending txs validated on top of confirmed state
        for p in self.mempool:
            trial.apply(p)
        trial.apply(tx)                    # raises RuleError if rejected
        self.mempool.append(tx)
        if gossip:
            for p in self.peers:
                try:
                    p.submit(Transaction.from_dict(tx.to_dict()), gossip=False)
                except RuleError:
                    pass
        return tx

    def mine_block(self, gossip=True):
        txs, self.mempool = self.mempool, []
        b = Block(len(self.chain), self.chain[-1].hash, txs).mine()
        self.chain.append(b)
        for t in txs:
            self.state.apply(t)
        if gossip:
            for p in self.peers:
                p.receive_block(Block.from_dict(b.to_dict()))
        return b

    def receive_block(self, b):
        cand = self.chain + [b]
        ok, _, state = validate_chain(cand, self.regulator)
        if ok:
            self.chain, self.state = cand, state
            ids = {t.tx_id for t in b.txs}
            self.mempool = [t for t in self.mempool if t.tx_id not in ids]
            return True
        return False

    def replace_chain(self, other_chain):
        """Longest valid chain wins."""
        ok, _, state = validate_chain(other_chain, self.regulator)
        if ok and len(other_chain) > len(self.chain):
            self.chain, self.state = other_chain, state
            return True
        return False


# ---- certificate helpers (off-chain document, on-chain hash) ----

def certificate_hash(cert: dict) -> str:
    """cert holds student name, id, programme, grade, year, institution and a random salt."""
    return sha256(canonical(cert))


def verify_certificate(node: Node, cert: dict):
    """Read-only check any employer can run against any node."""
    h = certificate_hash(cert)
    rec = node.state.certs.get(h)
    if rec is None:
        return "NOT FOUND", "no matching hash on the ledger (forged or altered document)"
    if rec["revoked"]:
        return "REVOKED", f"issued by {rec['issuer_name']}, revoked: {rec['revoke_reason']}"
    return "VALID", f"issued by {rec['issuer_name']} (tx {rec['issue_tx'][:12]}...)"
