import random
import logging
from boofuzz import *
from bgp_fuzz_test import BGFuzzTest

class BGPFuzzNotificationMessage(BGFuzzTest):
    def __init__(self, config_file):
        super().__init__(config_file)

    def fuzz_notification(self):
        """
        Generates a fuzz test for the BGP Notification message with multiple 
        optional parameters, each having a random payload.
        """
        s_initialize("BGP_NOTIFICATION")
        with s_block("BGP"):
            with s_block("Header"):
                s_bytes(value=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", padding=b"\xFF", size=16, name="Marker", fuzzable=False)
                s_size(block_name="Notification", length=2, math=lambda x: x + 19, name="Length", endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x03, endian=BIG_ENDIAN, name="Type", fuzzable=False)
            with s_block("Notification"):
                s_byte(name='error_code', value=0x00, fuzzable=False)
                s_byte(name='error_subcode', value=0x00, fuzzable=False)
                s_random(name='data', min_length=0, max_length=4096, num_mutations=4096, fuzzable=True)

        self.session.connect(s_get("BGP_NOTIFICATION"))
        self.session.fuzz()
