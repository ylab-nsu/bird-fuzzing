import time
from boofuzz import *
from scapy.all import *
import json
import random

# Loading configuration from file
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

BIRD_CON_NAME = config['BIRD_CON_NAME']
BGP_PROTO_NAME = config['BGP_PROTO_NAME']
BIRD_ASN_ID = config['BIRD_ASN_ID']
HOST_BGP_ID = config['HOST_BGP_ID']
PARAM_HOLD_TIME = config['PARAM_HOLD_TIME']
BIRD_BGP_ID = config['BIRD_BGP_ID']
BIRD_BGP_PORT = config['BIRD_BGP_PORT']


def restart_uplink(target=None, fuzz_data_logger=None, session=None, sock=None):
    """Function for restarting BGP protocol in container with bird"""
    try:
        subprocess.run(['docker', 'exec', BIRD_CON_NAME, 'birdc', 'restart', BGP_PROTO_NAME], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to restart {BGP_PROTO_NAME}: {e}")

log_buffer = []

def print_new_logs(target=None, fuzz_data_logger=None, session=None, sock=None):
    """Function for printing logs bird"""
    try:
        # Reading last string from logs file
        process = subprocess.Popen(
            ['docker', 'exec', '-i', BIRD_CON_NAME, 'tail', '-n1', '/var/log/bird.log'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output, _ = process.communicate()  # Reading last string
        log_entry = output.decode().strip()
        if log_entry:  # If string not empty print it
            print(log_entry)
    except Exception as e:
        print(f"Failed to read logs of container with bird{e}")

def ip_str_to_bytes(ip):
    """Transformation IP-address to bytes."""
    return int.from_bytes(socket.inet_aton(ip), 'big')

def fuzz_open_and_keepalive(dst_ip, dst_port):
    """Fuzz Open Message with Keepalive."""
    session = Session(
        target=Target(
            connection=TCPSocketConnection(host=dst_ip, port=dst_port)
        ),
        post_test_case_callbacks=[print_new_logs, restart_uplink],
    )

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
            s_word(value=BIRD_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
            s_dword(value=ip_str_to_bytes(HOST_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
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
    session.connect(s_get("bgp_open"))
    session.connect(s_get("bgp_open"), s_get("bgp_keepalive"))
    session.fuzz()


# Fuzzing test
fuzz_open_and_keepalive(BIRD_BGP_ID, BIRD_BGP_PORT)
