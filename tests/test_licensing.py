from app.db import Database
from app.licensing import gumroad_sale_fields


def test_gumroad_sale_fields_normalizes_payload():
    sale = gumroad_sale_fields({
        "license_key": "  OZHEX-TEST-KEY  ",
        "product_permalink": "ozhex-xdr-pro",
        "email": "Buyer@Example.COM",
        "order_number": "ORDER-1",
        "quantity": "2",
    })
    assert sale["license_key"] == "OZHEX-TEST-KEY"
    assert sale["product_permalink"] == "ozhex-xdr-pro"
    assert sale["email"] == "buyer@example.com"
    assert sale["order_number"] == "ORDER-1"
    assert sale["quantity"] == "2"


def test_license_registry_is_idempotent(tmp_path):
    db = Database(str(tmp_path / "xdr.db"))
    sale = gumroad_sale_fields({
        "license_key": "OZHEX-TEST-KEY",
        "product_permalink": "ozhex-xdr-pro",
        "email": "buyer@example.com",
        "order_number": "ORDER-1",
        "variants": "Professional",
        "quantity": "1",
    })
    first = db.upsert_gumroad_license(sale, {"license_key": sale["license_key"]})
    second = db.upsert_gumroad_license(sale, {"license_key": sale["license_key"]})
    assert first["id"] == second["id"]
    assert db.licenses() and len(db.licenses()) == 1
