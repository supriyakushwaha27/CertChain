
from flask import Flask, render_template, request, redirect, url_for, flash
import secrets

from certchain import (
    Wallet, Node, certificate_hash, verify_certificate
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Initialize the local blockchain and register VESIT as an issuer.
regulator = Wallet()
institution = Wallet()
node = Node("CertChain-Node", regulator.address)

node.submit(regulator.tx("ADD_INSTITUTION", {
    "address": institution.address,
    "name": "VESIT"
}))
node.mine_block()

# Demo-only storage for certificate details kept off-chain.
documents = {}


def make_certificate(form):
    return {
        "student": form.get("student", "").strip(),
        "id": form.get("certificate_id", "").strip(),
        "programme": form.get("programme", "").strip(),
        "grade": form.get("grade", "").strip(),
        "year": int(form.get("year", "2027")),
        "institution": "VESIT",
        "salt": form.get("salt", "").strip()
    }


@app.route("/")
def index():
    records = []
    for cert_hash, record in node.state.certs.items():
        details = documents.get(cert_hash, {})
        records.append({
            "hash": cert_hash,
            "student": details.get("student", "Private"),
            "certificate_id": details.get("id", "Hidden"),
            "programme": details.get("programme", "Hidden"),
            "revoked": record["revoked"],
            "issuer": record["issuer_name"],
            "issued_at": record["issued_at"]
        })

    return render_template(
        "index.html",
        records=records,
        blocks=node.chain,
        height=node.height(),
        institution="VESIT"
    )


@app.route("/issue", methods=["POST"])
def issue():
    try:
        cert = make_certificate(request.form)

        if not all(cert[k] for k in (
            "student", "id", "programme", "grade", "salt"
        )):
            flash("Please fill in every certificate field.", "error")
            return redirect(url_for("index"))

        cert_hash = certificate_hash(cert)

        if cert_hash in node.state.certs:
            flash("This certificate is already registered.", "error")
            return redirect(url_for("index"))

        node.submit(institution.tx("ISSUE_CERT", {
            "cert_hash": cert_hash
        }))
        node.mine_block()
        documents[cert_hash] = cert

        flash(
            f"Certificate {cert['id']} registered successfully. "
            f"Hash: {cert_hash}",
            "success"
        )

    except (ValueError, KeyError) as exc:
        flash(f"Invalid certificate details: {exc}", "error")

    return redirect(url_for("index"))


@app.route("/verify", methods=["POST"])
def verify():
    try:
        cert = make_certificate(request.form)
        cert_hash = certificate_hash(cert)
        status, message = verify_certificate(node, cert)

        if status == "VALID":
            flash(f"VALID: {message}", "success")
        elif status == "REVOKED":
            flash(f"REVOKED: {message}", "error")
        else:
            flash(
                "NOT FOUND: The details do not match a registered "
                "certificate. Check the information and salt.",
                "error"
            )

    except (ValueError, KeyError) as exc:
        flash(f"Invalid verification details: {exc}", "error")

    return redirect(url_for("index"))


@app.route("/revoke", methods=["POST"])
def revoke():
    cert_hash = request.form.get("cert_hash", "").strip()
    reason = request.form.get("reason", "").strip()

    record = node.state.certs.get(cert_hash)

    if not record:
        flash("Certificate hash not found.", "error")
    elif record["revoked"]:
        flash("Certificate is already revoked.", "error")
    else:
        try:
            node.submit(institution.tx("REVOKE_CERT", {
                "cert_hash": cert_hash,
                "reason": reason or "Revoked by issuer"
            }))
            node.mine_block()
            flash("Certificate revoked successfully.", "success")
        except Exception as exc:
            flash(f"Revocation failed: {exc}", "error")

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
