import unittest
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app, init, evaluate


class DecisionEngineTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.testing = True
        self.ctx = app.app_context()
        self.ctx.push()
        init()
        # Reset test transactions for pristine evaluation
        from app import db
        db().execute("DELETE FROM transactions")
        db().commit()

    def tearDown(self):
        self.ctx.pop()

    def test_safe_purchase_is_allowed(self):
        result = evaluate({
            "agent_id": 1, "amount": 45000, "quantity": 5,
            "unit_price": 9000, "category": "Electronics",
            "vendor": "Acme Approved Vendors", "intent": "Equip design team"
        })
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["approved_amount"], 45000)

    def test_single_item_over_limit_requires_approval(self):
        result = evaluate({
            "agent_id": 1, "amount": 65000, "quantity": 1,
            "unit_price": 65000, "category": "Electronics",
            "vendor": "Acme Approved Vendors", "intent": "Buy enterprise laptop"
        })
        self.assertEqual(result["decision"], "APPROVAL_REQUIRED")

    def test_smart_modify_for_bulk_over_limit(self):
        result = evaluate({
            "agent_id": 1, "amount": 90000, "quantity": 10,
            "unit_price": 9000, "category": "Electronics",
            "vendor": "Acme Approved Vendors", "intent": "Buy monitors"
        })
        self.assertEqual(result["decision"], "MODIFY")
        self.assertEqual(result["suggested_modification"]["suggested_quantity"], 5)

    def test_unknown_vendor_is_blocked(self):
        result = evaluate({
            "agent_id": 1, "amount": 18000, "quantity": 2,
            "unit_price": 9000, "category": "Electronics",
            "vendor": "Unknown Vendor", "intent": "Buy monitors"
        })
        self.assertEqual(result["decision"], "BLOCK")

    def test_invalid_agent_is_blocked(self):
        result = evaluate({
            "agent_id": 99999, "amount": 1000, "quantity": 1,
            "unit_price": 1000, "category": "Office Equipment",
            "vendor": "Acme Approved Vendors", "intent": "Test"
        })
        self.assertEqual(result["decision"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
