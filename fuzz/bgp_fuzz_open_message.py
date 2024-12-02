import random
from boofuzz import *
from bgp_fuzz_test import BGFuzzTest

class BGPFuzzOpenMessage(BGFuzzTest):
    def __init__(self, config_file):
        super().__init__(config_file)

    def fuzz_open_and_keepalive(self):
        """Fuzz Open Message with Keepalive."""
        # Open Message
        s_initialize('bgp_open')
        if s_block_start('BGP'):
            if s_block_start('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            s_block_end()
            if s_block_start('Open'):
                s_byte(value=0x04, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=b'\xff', endian='>', name='Non-Ext OP Len', fuzzable=False)
                s_byte(value=b'\xff', endian='>', name = 'Non-Ext OP Type', fuzzable=False)
                s_size(block_name='Optional Parameters', length=2, name='Extended Opt. Parm Length', endian=BIG_ENDIAN, fuzzable=False)
                if s_block_start('Optional Parameters'):
                    for param_i in range(random.randint(1, 5)):
                        if s_block_start(f'Reserved {param_i}'):
                            s_byte(value=0x00, endian=BIG_ENDIAN, name='Parameter Type', fuzzable=False)
                            s_size(block_name=f'Reserved Parameter Value {param_i}', length=1, name='Parameter Length', endian=BIG_ENDIAN, fuzzable=True)
                            s_string(value='', name=f'Reserved Parameter Value {param_i}', padding=b'\x00', fuzzable=True, max_len=1500)
                        s_block_end()
                s_block_end()
            s_block_end()
        s_block_end()

        s_initialize('bgp_keepalive')
        if s_block_start('BGP'):
            if s_block_start('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Keepalive', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x04, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            s_block_end()
            if s_block_start('Keepalive'):
                pass
            s_block_end()
        s_block_end()
        # Connection Open -> Keepalive
        self.session.connect(s_get("bgp_open"))
        self.session.connect(s_get("bgp_open"), s_get("bgp_keepalive"))
        self.session.fuzz()
