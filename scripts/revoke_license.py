from __future__ import annotations

import argparse
import os
from pathlib import Path

from app.license_tokens import sign_revocation_manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--license-id", required=True)
    parser.add_argument("--file", default="licenses/revocations.ozhx")
    args = parser.parse_args()

    path = Path(args.file)
    existing = []
    if path.exists():
        text = path.read_text(encoding="utf-8").strip()
        if text:
            from app.license_tokens import verify_revocation_manifest
            public_key = os.environ["OZHEX_LICENSE_PUBLIC_KEY"]
            existing = sorted(verify_revocation_manifest(text, public_key))
    if args.license_id not in existing:
        existing.append(args.license_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(sign_revocation_manifest(existing, os.environ["OZHEX_LICENSE_PRIVATE_KEY"]) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
