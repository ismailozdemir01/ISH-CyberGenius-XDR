from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import timedelta

from app.license_tokens import customer_hash, iso, license_id, sign_payload, utcnow


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--product", default="OZHEX-CyberGenius-XDR")
    parser.add_argument("--plan", default="Professional")
    parser.add_argument("--days", type=int, default=0)
    parser.add_argument("--max-activations", type=int, default=3)
    parser.add_argument("--order-number", default="")
    parser.add_argument("--gumroad-license", default="")
    parser.add_argument("--output", default="ozhex-license.lic")
    args = parser.parse_args()

    private_key = os.environ["OZHEX_LICENSE_PRIVATE_KEY"]
    now = utcnow()
    expires = None if args.days <= 0 else iso(now + timedelta(days=args.days))
    payload = {
        "v": 1,
        "license_id": license_id(),
        "product": args.product,
        "plan": args.plan,
        "customer": customer_hash(args.email),
        "issued_at": iso(now),
        "expires_at": expires,
        "max_activations": max(1, args.max_activations),
        "order": hashlib.sha256(args.order_number.encode()).hexdigest() if args.order_number else None,
        "gumroad_license": hashlib.sha256(args.gumroad_license.encode()).hexdigest() if args.gumroad_license else None,
    }
    token = sign_payload(payload, private_key)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    with open(args.output + ".json", "w", encoding="utf-8") as handle:
        json.dump({**payload, "token_sha256": hashlib.sha256(token.encode()).hexdigest()}, handle, indent=2)
    print(json.dumps({**payload, "token_sha256": hashlib.sha256(token.encode()).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()
