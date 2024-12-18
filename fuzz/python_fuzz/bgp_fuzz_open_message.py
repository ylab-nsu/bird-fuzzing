import random
import logging
from boofuzz import *
from bgp_fuzz_test import BGFuzzTest

# Константы
BGP_HEADER_SIZE = 16
BGP_VERSION = 0x04
BGP_TYPE = 0x01
MAX_BGP_OPTIONAL_PARAM_LEN = 4096
MAX_ASN_VALUE = 65535
MAX_HOLD_TIME = 65535
MAX_BGP_ID = 0xFFFFFFFF
DEFAULT_HOLD_TIME = 90

class BGPFuzzOpenMessage(BGFuzzTest):
    def __init__(self, config_file):
        super().__init__(config_file)

    def initialize_bgp_header(self, block_name):
        with s_block(block_name):
            s_bytes(value=b'\xFF' * BGP_HEADER_SIZE, padding=b'\xFF', size=BGP_HEADER_SIZE, name='Marker', fuzzable=False)
            s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
            s_byte(value=BGP_TYPE, endian=BIG_ENDIAN, name='Type', fuzzable=False)

    def fuzz_bgp_open_with_optional_params(self):
        """
        Fuzzes the BGP Open message with multiple optional parameters,
        each having a random payload.
        """
        s_initialize('bgp_open')
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            with s_block('Open'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=b'\xff', endian='>', name='Non-Ext OP Len', fuzzable=False)
                s_byte(value=b'\xff', endian='>', name='Non-Ext OP Type', fuzzable=False)
                s_size(block_name='Optional Parameters', length=2, name='Extended Opt. Parm Length', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('Optional Parameters'):
                    for param_i in range(random.randint(1, 5)):
                        with s_block(f'Reserved {param_i}'):
                            s_byte(value=0x00, endian=BIG_ENDIAN, name='Parameter Type', fuzzable=False)
                            s_size(block_name=f'Reserved Parameter Value {param_i}', length=1, name='Parameter Length', endian=BIG_ENDIAN, fuzzable=True)
                            s_string(value='', name=f'Reserved Parameter Value {param_i}', padding=b'\x00', fuzzable=True, max_len=1500)

        s_initialize('bgp_keepalive')
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            with s_block('Keepalive'):
                pass

        self.session.connect(s_get('bgp_open'))
        self.session.connect(s_get('bgp_open'), s_get('bgp_keepalive'))
        self.session.fuzz()

    def fuzz_bgp_open_optional_param_length(self):
        """
        Fuzzes the length of optional parameters (1 octet) and their payload.
        """
        s_initialize('bgp_open')
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            with s_block('Open'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=b'\x00', endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=True)
            with s_block('Optional Parameters'):
                s_random(name='params', max_length=MAX_BGP_OPTIONAL_PARAM_LEN, num_mutations=4096, fuzzable=True)

        self.session.connect(s_get('bgp_open'))
        self.session.fuzz()

    def fuzz_bgp_open_random_params(self):
        """
        Fuzzes optional parameters with random payload and length.
        """
        s_initialize('bgp_open')
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            with s_block('Open'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_random(name='params', max_length=MAX_BGP_OPTIONAL_PARAM_LEN, num_mutations=4096, fuzzable=True)

        self.session.connect(s_get('bgp_open'))
        self.session.fuzz()

    def fuzz_bgp_open_version_field(self):
        """
        Fuzzes the BGP version field with random and boundary values.
        """
        s_initialize('bgp_open')
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            with s_block('Open'):
                # Fuzz the version field
                s_byte(value=random.choice([0x01, 0x04, 0xFF]), endian=BIG_ENDIAN, name='Version', fuzzable=True)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')

        self.session.connect(s_get('bgp_open'))
        self.session.fuzz()

    def fuzz_bgp_open_length_mismatch(self):
        """
        Fuzzes the BGP header length to create a mismatch with the actual message size.
        """
        s_initialize('bgp_open')
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            # Fuzz the length field
            s_word(value=random.randint(20, 100), endian=BIG_ENDIAN, name='Length', fuzzable=True)
            s_byte(value=BGP_TYPE, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            with s_block('Open'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='Version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')

        self.session.connect(s_get('bgp_open'))
        self.session.fuzz()

    def fuzz_open_asn(self):
        '''
        Fuzz ASN field with boundary and random values.
        '''
        s_initialize('bgp_open')
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            with s_block('Open'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='Version', fuzzable=False)
                # Fuzz ASN field
                s_word(value=random.randint(0, MAX_ASN_VALUE), endian=BIG_ENDIAN, name='ASN', fuzzable=True)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')

        self.session.connect(s_get('bgp_open'))
        self.session.fuzz()

    def fuzz_open_hold_time(self):
        '''
        Fuzz Hold Time field with boundary and random values.
        '''
        s_initialize('bgp_open')
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            with s_block('Open'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='Version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                # Fuzz Hold Time field
                s_word(value=random.randint(0, MAX_HOLD_TIME), endian=BIG_ENDIAN, name='Hold Time', fuzzable=True)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')

        s_initialize('BGP_KEEPALIVE')                                                                        
        with s_block('Header'):                                                                                     
            s_static(name='marker', value=b'\xff'*16)                                                               
            s_static(name='length', value=b'\x00\x13')                            
            s_static(name='type', value=b'\x04')  

        self.session.connect(s_get('bgp_open'))
        self.session.connect(s_get('bgp_open'), s_get('BGP_KEEPALIVE'))
        self.session.fuzz()

    def fuzz_open_identifier(self):
        '''
        Fuzz BGP Identifier field with random values and invalid IPs.
        '''
        s_initialize('bgp_open')
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            with s_block('Open'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='Version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                # Fuzz BGP Identifier field with invalid values
                s_dword(value=random.randint(0, MAX_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=True)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')

        self.session.connect(s_get('bgp_open'))
        self.session.fuzz()

    def fuzz_open_version_length(self):
        """
        Fuzzes the BGP version field and the packet length field with mismatched values.
        """
        s_initialize('bgp_open')
        with s_block('BGP'):
            with s_block('Header'):
                s_bytes(value=b'\xFF'*16, padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                
                s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=True)
                
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            
            with s_block('Open'):
                s_byte(value=random.choice([0x00, 0xFF, 0x01, 0x04]), endian=BIG_ENDIAN, name='Version', fuzzable=True)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)

                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')
        
        s_initialize('bgp_open_with_length_mismatch')
        with s_block('BGP'):
            with s_block('Header'):
                s_bytes(value=b'\xFF'*16, padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                
                s_word(value=random.randint(50, 1000), endian=BIG_ENDIAN, name='Length', fuzzable=True)
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            
            with s_block('Open'):
                s_byte(value=0x04, endian=BIG_ENDIAN, name='Version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)

                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')

        self.session.connect(s_get('bgp_open'))
        self.session.connect(s_get('bgp_open_with_length_mismatch'))
        self.session.fuzz()
