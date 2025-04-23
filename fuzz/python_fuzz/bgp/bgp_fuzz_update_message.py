from boofuzz import *
from .bgp_fuzz_test import BGFuzzTest

BGP_HEADER_SIZE = 16
BGP_VERSION = 0x04
BGP_TYPE = 0x01
MAX_BGP_OPTIONAL_PARAM_LEN = 4096
MAX_ASN_VALUE = 65535
MAX_HOLD_TIME = 65535
MAX_BGP_ID = 0xFFFFFFFF
DEFAULT_HOLD_TIME = 90


class BgpUpdateFuzzer(BGFuzzTest):
    def __init__(self, config_file, test_results, max_tests=100):
        super().__init__(config_file, max_tests)
        self.test_results = test_results

    @staticmethod
    def initialize_bgp_header(block_name):
        with s_block(block_name):
            s_bytes(value=b'\xFF' * BGP_HEADER_SIZE, padding=b'\xFF', size=BGP_HEADER_SIZE, name='Marker',
                    fuzzable=False)
            s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
            s_byte(value=BGP_TYPE, endian=BIG_ENDIAN, name='Type', fuzzable=False)

    def create_bgp_open(self, n):
        s_initialize('bgp_open_' + str(n))
        with s_block('BGP'):
            self.initialize_bgp_header('Header')
            with s_block('Open'):
                s_byte(value=BGP_VERSION, endian=BIG_ENDIAN, name='Version', fuzzable=False)
                s_word(value=self.FUZZER_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=self.PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=self.ip_str_to_bytes(self.HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier',
                        fuzzable=False)
                s_byte(value=0x00, endian=BIG_ENDIAN, name='Opt Parm Len', fuzzable=False)
                with s_block('Optional Parameters'):
                    s_static(value=b'', name='Params')
        return s_get('bgp_open_' + str(n))

    @staticmethod
    def create_bgp_keepalive(n):
        s_initialize('BGP_KEEPALIVE' + str(n))
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_static(name='length', value=b'\x00\x13')
            s_static(name='type', value=b'\x04')
        return s_get('BGP_KEEPALIVE' + str(n))

    def update_test_fuzz_withdrawn_routes_length(self):
        """
        Test for fuzzing the Withdrawn Routes Length field.
        """
        s_initialize('BGP_UPDATE_fuzz_withdrawn_len')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_random(value='', min_length=2, max_length=2, num_mutations=100000, name='withdrawn_routes_length', fuzzable=True)
                with s_block('withdrawn_routes'):
                    s_static(name='prefix1_len', value=b'\x20')  # 32-bit length
                    s_static(name='prefix1_addr', value=b'\xc0\xa8\x01\x01')  # 192.168.1.1
                s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZLOAD'):
                    s_static(value=b'', name='Params')  # Empty field for attributes
        # Set the message sequence
        self.session.connect(self.create_bgp_open(1))
        self.session.connect(s_get('bgp_open_1'), self.create_bgp_keepalive(1))
        self.session.connect(s_get('BGP_KEEPALIVE1'), s_get('BGP_UPDATE_fuzz_withdrawn_len'))
        self.fuzz('BGP_UPDATE_fuzz_withdrawn_len')

    def update_test_fuzz_withdrawn_routes(self):
        """
        Test for fuzzing the Withdrawn Routes field (prefixes to be withdrawn).
        """
        s_initialize('BGP_UPDATE_fuzz_withdrawn_routes')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_static(name='withdrawn_routes_length', value=b'\x00\x08')  # Static field (2 prefixes of 4 bytes each)
                with s_block('withdrawn_routes'):
                    s_byte(name='prefix1_len', value=32, fuzzable=True)  # Fuzzing prefix length
                    s_bytes(name='prefix1_addr', value=b'\xc0\xa8\x01\x01', size=4,
                            fuzzable=True)  # Fuzzing prefix address
                s_size(name='total_path_attr_len', length=2, block_name='FUZZ__LOAD', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZ__LOAD'):
                    s_static(value=b'', name='Params')  # Empty field for attributes
        # Set the message sequence
        self.session.connect(self.create_bgp_open(2))
        self.session.connect(s_get('bgp_open_2'), self.create_bgp_keepalive(2))
        self.session.connect(s_get('BGP_KEEPALIVE2'), s_get('BGP_UPDATE_fuzz_withdrawn_routes'))
        self.fuzz('BGP_UPDATE_fuzz_withdrawn_routes')

    def update_test_fuzz_path_attributes_length(self):
        """
        Test for fuzzing the Path Attributes Length field.
        """
        s_initialize('BGP_UPDATE_fuzz_path_attr_len')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_static(name='withdrawn_routes_length', value=b'\x00\x00')  # Static field
                s_random(value='', min_length=2, max_length=2, num_mutations=100000, name='total_path_attr_len', fuzzable=True)
                with s_block('FUZZ LOAD'):
                    s_static(value=b'', name='Params')  # Empty field for attributes
        # Set the message sequence
        self.session.connect(self.create_bgp_open(3))
        self.session.connect(s_get('bgp_open_3'), self.create_bgp_keepalive(3))
        self.session.connect(s_get('BGP_KEEPALIVE3'), s_get('BGP_UPDATE_fuzz_path_attr_len'))
        self.fuzz('BGP_UPDATE_fuzz_path_attr_len')

    def update_test_fuzz_path_attributes(self):
        """
        Test for fuzzing the Path Attributes fields.
        """
        s_initialize('BGP_UPDATE_fuzz_path_attrs')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_static(name='withdrawn_routes_length', value=b'\x00\x00')  # Static field
                s_size(name='total_path_attr_len', length=2, block_name='path_attributes', endian=BIG_ENDIAN,
                       fuzzable=False)
                with s_block('path_attributes'):
                    s_byte(name='attr_flags', value=0x40, fuzzable=True)  # Fuzzing flags
                    s_byte(name='attr_type', value=0x01, fuzzable=True)  # Fuzzing type
                    s_byte(name='attr_length', value=1, fuzzable=True)  # Fuzzing length
                    s_byte(name='attr_value', value=0x00, fuzzable=True)  # Fuzzing value
                s_size(name='total_path_attr_len2', length=2, block_name='FUZZ_LOAD2', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZ_LOAD2'):
                    s_static(value=b'', name='Params')  # Empty field for attributes
        # Set the message sequence
        self.session.connect(self.create_bgp_open(4))
        self.session.connect(s_get('bgp_open_4'), self.create_bgp_keepalive(4))
        self.session.connect(s_get('BGP_KEEPALIVE4'), s_get('BGP_UPDATE_fuzz_path_attrs'))
        self.fuzz('BGP_UPDATE_fuzz_path_attrs')

    def update_test_fuzz_nlri(self):
        """
        Test for fuzzing the NLRI field.
        """
        s_initialize('BGP_UPDATE_fuzz_nlri')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_static(name='withdrawn_routes_length', value=b'\x00\x00')  # Static field
                s_size(name='total_path_attr_len', length=2, block_name='FUZZ-LOAD3', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZ-LOAD3'):
                    s_static(value=b'', name='Params')  # Empty field for attributes
                s_byte(name='nlri_prefix_len', value=24, fuzzable=True)  # Fuzzing prefix length
                s_bytes(name='nlri_prefix_addr', value=b'\xc0\xa8\x02', size=3, fuzzable=True)  # Fuzzing prefix address
        # Set the message sequence
        self.session.connect(self.create_bgp_open(5))
        self.session.connect(s_get('bgp_open_5'), self.create_bgp_keepalive(5))
        self.session.connect(s_get('BGP_KEEPALIVE5'), s_get('BGP_UPDATE_fuzz_nlri'))
        self.fuzz('BGP_UPDATE_fuzz_nlri')
