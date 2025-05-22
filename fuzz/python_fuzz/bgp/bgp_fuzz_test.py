import socket
import time

from boofuzz import Session, Target, TCPSocketConnection
import json
import paramiko
from app.custom_logger import CustomFuzzLogger


class BGFuzzTest:
    def __init__(self, config_file, max_tests=100):
        self.test_results = None
        with open(config_file, 'r') as f:
            config = json.load(f)

        # Loading parameters from config
        self.BIRD_BGP_ID = config['BIRD_BGP_ID']
        self.BIRD_BGP_PORT = config['BIRD_BGP_PORT']
        self.HOST_BGP_ID = config['HOST_BGP_ID']
        self.FUZZER_ASN_ID = config['FUZZER_ASN_ID']
        self.PARAM_HOLD_TIME = config['PARAM_HOLD_TIME']
        self.BIRD_CON_NAME = config['BIRD_CON_NAME']
        self.BGP_PROTO_NAME = config['BGP_PROTO_NAME']
        self.BIRD_USER = 'root'
        self.BIRD_IP = config['BIRD_BGP_ID']
        self.BIRD_PASSWORD = 'password'
        self.log_file = "logs.txt"
        self.max_tests = max_tests
        self.test_counter = 0

        self.logger = CustomFuzzLogger(self.log_file)

        self.session = Session(
            target=Target(
                connection=TCPSocketConnection(host=self.BIRD_BGP_ID, port=self.BIRD_BGP_PORT)
            ),
            index_start=1,
            index_end=self.max_tests,
            web_port=None,
            post_test_case_callbacks=[self.print_new_logs, self.restart_uplink],
            fuzz_loggers=[self.logger]
        )

    def fuzz(self, name):
        start_time = time.time()
        try:
            self.session.fuzz()
            status = "Success"
        except Exception as e:
            status = f"Failed: {e}"
        finally:
            elapsed_time = time.time() - start_time
            self.test_results.add_result(name, status, self.max_tests, str(elapsed_time))
            print(f"Test {name} {self.max_tests} {status} {elapsed_time:.2f} seconds")

    @staticmethod
    def ip_str_to_bytes(ip):
        """Transformation IP-address to bytes."""
        return int.from_bytes(socket.inet_aton(ip), 'big')

    def get_ssh_client(self):
        """ Make and return SSH-client for connection to Docker container"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.BIRD_IP, username=self.BIRD_USER, password=self.BIRD_PASSWORD)
            return client
        except Exception as e:
            print(f"Failed to connect to SSH: {e}")
            return None

    def print_new_logs(self, target=None, fuzz_data_logger=None, session=None, sock=None):
        """Function for printing logs bird through SSH"""
        try:
            client = self.get_ssh_client()
            if client:
                stdin, stdout, stderr = client.exec_command('tail -n1 /var/log/bird.log')
                log_entry = stdout.read().decode().strip()
                if log_entry:
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(log_entry + "\n")
                client.close()
        except Exception as e:
            print(f"Failed to read logs of container with bird via SSH: {e}")

    def restart_uplink(self, target=None, fuzz_data_logger=None, session=None, sock=None):
        """Function for restarting BGP protocol in container with bird via SSH"""
        try:
            client = self.get_ssh_client()
            if client:
                stdin, stdout, stderr = client.exec_command(f'birdc restart {self.BGP_PROTO_NAME}')
                client.close()
        except Exception as e:
            print(f"Failed to restart BGP_PROTO_NAME via SSH: {e}")
