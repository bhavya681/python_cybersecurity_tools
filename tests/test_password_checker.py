import unittest
from modules.password_checker import PasswordStrengthChecker

class TestPasswordChecker(unittest.TestCase):
    def test_strength(self):
        c = PasswordStrengthChecker()
        res = c.check_strength("Aa1!verystrongpass")
        self.assertGreaterEqual(res["score"], 4)

if __name__ == "__main__":
    unittest.main()
