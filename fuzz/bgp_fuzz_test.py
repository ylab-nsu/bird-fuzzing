import subprocess
import socket
from boofuzz import Session, Target, TCPSocketConnection
import json

class BGFuzzTest:
    def __init__(self, config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # Loading parameters from config
        self.BIRD_BGP_ID = config['BIRD_BGP_ID']
        self.BIRD_BGP_PORT = config['BIRD_BGP_PORT']
        self.HOST_BGP_ID = config['HOST_BGP_ID']
        self.BIRD_ASN_ID = config['BIRD_ASN_ID']
        self.PARAM_HOLD_TIME = config['PARAM_HOLD_TIME']
        self.BIRD_CON_NAME = config['BIRD_CON_NAME']
        self.BGP_PROTO_NAME = config['BGP_PROTO_NAME']
        
        self.session = Session(
            target=Target(
                connection=TCPSocketConnection(host=self.BIRD_BGP_ID, port=self.BIRD_BGP_PORT)
            ),
            post_test_case_callbacks=[self.print_new_logs, self.restart_uplink],
        )

    def ip_str_to_bytes(self, ip):
        """Transformation IP-address to bytes."""
        return int.from_bytes(socket.inet_aton(ip), 'big')

    def print_new_logs(self, target=None, fuzz_data_logger=None, session=None, sock=None):
        """Function for printing logs bird"""
        try:
            # Reading last string from logs file
            process = subprocess.Popen(
                ['docker', 'exec', '-i', self.BIRD_CON_NAME, 'tail', '-n1', '/var/log/bird.log'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = process.communicate()  # Reading last string
            log_entry = output.decode().strip()
            if log_entry:  # If string not empty print it
                print(log_entry)
        except Exception as e:
            print(f"Failed to read logs of container with bird: {e}")

    def restart_uplink(self, target=None, fuzz_data_logger=None, session=None, sock=None):
        """Function for restarting BGP protocol in container with bird"""
        try:
            subprocess.run(['docker', 'exec', self.BIRD_CON_NAME, 'birdc', 'restart', self.BGP_PROTO_NAME], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to restart BGP_PROTO_NAME: {e}")
