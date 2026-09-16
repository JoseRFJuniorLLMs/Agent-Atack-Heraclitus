import unittest
from attacks.protocol import _status_from_raw
class ProtocolTests(unittest.TestCase):
 def test_status_parser(self):self.assertEqual(_status_from_raw(b"HTTP/1.1 403 Forbidden\r\nX: y\r\n\r\n"),403);self.assertIsNone(_status_from_raw(b"garbage"))
if __name__=="__main__":unittest.main()
