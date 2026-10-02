import plistlib,unittest
from server_announcement import Announcement,UnknownMessage,MalformedAnnouncement,decode_message
class AnnouncementTests(unittest.TestCase):
 def test_dict_and_unknown_keys_preserved(self):
  fields={'worldID':'fixture','ownerName':'local owner','extension':b'\x00\xff'}
  for fmt in (plistlib.FMT_XML,plistlib.FMT_BINARY):
   raw=b'\x23\x26'+plistlib.dumps(fields,fmt=fmt);msg=decode_message(raw)
   self.assertIsInstance(msg,Announcement);self.assertEqual(msg.raw,raw);self.assertEqual(msg.fields,fields)
 def test_optional_fields_not_invented(self):
  msg=decode_message(b'\x23\x26'+plistlib.dumps({}));self.assertEqual(msg.fields,{})
 def test_unknown_messages_remain_opaque(self):
  for raw in (b'',b'\x23',b'\x23\x27anything',b'\x00\x26'):
   msg=decode_message(raw);self.assertIsInstance(msg,UnknownMessage);self.assertEqual(msg.raw,raw)
 def test_known_malformed_not_silently_unknown(self):
  for raw in (b'',b'not plist',b'<?xml',plistlib.dumps(['wrong shape'])):
   with self.assertRaises(MalformedAnnouncement):decode_message(b'\x23\x26'+raw)
 def test_mutable_buffer_not_retained(self):
  with self.assertRaises(TypeError):decode_message(bytearray(b'\x23\x26'))
if __name__=='__main__':unittest.main()
