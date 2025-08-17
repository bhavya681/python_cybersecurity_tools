import os, json, unittest, tempfile
from modules.auth import UserAuth

class TestAuth(unittest.TestCase):
    def test_register_and_login(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "users.json")
            auth = UserAuth(f)
            self.assertTrue(auth.register("alice", "secret123!"))
            self.assertFalse(auth.register("alice", "something"))
            user = auth.verify("alice", "secret123!")
            self.assertIsNotNone(user)
            self.assertIsNone(auth.verify("alice", "badpass"))
            self.assertIsNone(auth.verify("bob", "secret"))
if __name__ == "__main__":
    unittest.main()
