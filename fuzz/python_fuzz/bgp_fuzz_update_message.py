import random
from boofuzz import *
from bgp_fuzz_test import BGFuzzTest

class BgpUpdateFuzzer(BGFuzzTest):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_1_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
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

        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session_handle.fuzz()
