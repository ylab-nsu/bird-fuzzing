import random
from boofuzz import *
from bgp_fuzz_test import BGFuzzTest
from boofuzz import helpers

# Константы
BGP_HEADER_SIZE = 16
BGP_VERSION = 0x04
BGP_TYPE = 0x01
MAX_BGP_OPTIONAL_PARAM_LEN = 4096
MAX_ASN_VALUE = 65535
MAX_HOLD_TIME = 65535
MAX_BGP_ID = 0xFFFFFFFF
DEFAULT_HOLD_TIME = 90


class BgpUpdateFuzzer(BGFuzzTest):
    def __init__(self, config_file):
        super().__init__(config_file)

    def initialize_bgp_header(self, block_name):
        with s_block(block_name):
            s_bytes(value=0xFF * BGP_HEADER_SIZE, padding=0xFF, size=BGP_HEADER_SIZE, name='Marker', fuzzable=False)
            s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
            s_byte(value=BGP_TYPE, endian=BIG_ENDIAN, name='Type', fuzzable=False)

    def fuzz_bgp_messages(self):
        """
        Fuzzes the BGP Open message with multiple optional parameters,
        each having a random payload.
        """
        PARAM_ASN_ID = self.BIRD_ASN_ID
        PARAM_BGP_ID = self.HOST_BGP_ID
        PARAM_HOLD_TIME = self.PARAM_HOLD_TIME

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')
            with s_block('OPEN_MSG'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='Version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')                                                            
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  
           with s_block('FUZZLOAD'):
               s_random(min_length=0, max_length=1024, num_mutations=1024, fuzzable=True)

        self.session.connect(s_get('BGP_OPEN'))
        self.session.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session.fuzz()


    def fuzz_bgp_messages2(self):
        """
        Fuzzes the BGP Open message with multiple optional parameters,
        each having a random payload.
        """
        PARAM_ASN_ID = self.BIRD_ASN_ID
        PARAM_BGP_ID = self.HOST_BGP_ID
        PARAM_HOLD_TIME = self.PARAM_HOLD_TIME

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')
            with s_block('OPEN_MSG'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='Version', fuzzable=False)
                s_word(value=self.BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')                                                            
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  

           with s_block('UPDATE'):
               s_word(name='withdrawn_len', value=b'\x00\x00', endian=BIG_ENDIAN, fuzzable=False)          
               s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
               with s_block('FUZZLOAD'):
                   s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)

        self.session.connect(s_get('BGP_OPEN'))
        self.session.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session.fuzz()




