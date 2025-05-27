import json
import socket
import paramiko
from boofuzz import *
from app.custom_logger import CustomFuzzLogger

BFD_MIN_PACKET_LEN = 24
BFD_VERSION = 1
BFD_DIAG_NO_DIAG = 0
BFD_STATE_ADMIN_DOWN = 0
BFD_STATE_DOWN = 1
BFD_STATE_INIT = 2
BFD_STATE_UP = 3


class CustomUDPSocketConnection(UDPSocketConnection):
    def __init__(self, host, port, ttl=255, tos=0xC0, **kwargs):
        super().__init__(host=host, port=port, **kwargs)
        self.ttl = ttl
        self.tos = tos

    def open(self):
        super().open()
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, self.tos)


class BFDFuzzTest:
    def __init__(self, config_file=None, max_tests=1000):
        with open(config_file, "r") as f:
            config = json.load(f)

        self.config_file = config_file
        self.max_tests = max_tests
        self.BIRD_USER = "root"
        self.BIRD_IP = config["BIRD_BGP_ID"]
        self.BIRD_PASSWORD = "password"
        self.log_file = "bfd_fuzz_logs.txt"
        self.logger = CustomFuzzLogger(self.log_file)
        self.server_my_disc = self._get_discriminator_passively()
        if self.server_my_disc is None:
            raise RuntimeError("Failed to get BFD Discriminator from server")

        self.my_discriminator = 0x20C00318

        print(f"[+] Server's My Discriminator: 0x{self.server_my_disc:08X}")
        print(f"[+] Our My Discriminator: 0x{self.my_discriminator:08X}")

        self.session = Session(
            target=Target(
                connection=CustomUDPSocketConnection(
                    "192.168.100.10", 3784, ttl=255, tos=0xC0
                )
            ),
            index_start=1,
            index_end=self.max_tests,
            web_port=None,
            post_test_case_callbacks=[self.print_new_logs, self.restart_uplink],
            fuzz_loggers=[self.logger],
        )

    def get_ssh_client(self):
        """Function for printing logs bird through SSH"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )  # Доверяемся неизвестному ключу хоста
            client.connect(
                self.BIRD_IP, username=self.BIRD_USER, password=self.BIRD_PASSWORD
            )
            return client
        except Exception as e:
            print(f"Failed to connect to SSH: {e}")
            return None

    def print_new_logs(
        self, target=None, fuzz_data_logger=None, session=None, sock=None
    ):
        """Function for printing logs bird through SSH"""
        try:
            # Подключаемся по SSH
            client = self.get_ssh_client()
            if client:
                stdin, stdout, stderr = client.exec_command(
                    "tail -n1 /var/log/bird.log"
                )
                log_entry = stdout.read().decode().strip()
                if log_entry:
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(log_entry + "\n")
                client.close()
        except Exception as e:
            print(f"Failed to read logs of container with bird via SSH: {e}")

    def restart_uplink(
        self, target=None, fuzz_data_logger=None, session=None, sock=None
    ):
        """Function for restarting BGP protocol in container with bird via SSH"""
        try:
            client = self.get_ssh_client()
            if client:
                stdin, stdout, stderr = client.exec_command(f"birdc restart bfd1")
                client.close()
        except Exception as e:
            print(f"Failed to restart BGP_PROTO_NAME via SSH: {e}")

    def _get_discriminator_passively(self, timeout=10, retries=3):
        """Passive getting server's Discriminator"""
        for attempt in range(retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.bind(("0.0.0.0", 3784))
                    sock.settimeout(timeout)
                    data, (src_ip, src_port) = sock.recvfrom(1024)

                    if self._is_valid_bfd_packet(data):
                        server_my_disc = int.from_bytes(data[4:8], "big")
                        return server_my_disc
                    else:
                        print("[!]Got incorrect BFD packet")
            except socket.timeout:
                print(f"[{attempt + 1}/{retries}] Timeout waiting for BFD packet")
            except Exception as e:
                print(f"[!] Error: {str(e)}")

        return None

    @staticmethod
    def _is_valid_bfd_packet(data):
        """Validation BFD packet"""
        if len(data) < 24:
            return False
        version = (data[0] >> 5) & 0x07
        length = data[3]
        return version == 1 and length >= 24

    def fuzz_version_diag(self):
        """Fuzzing Version + Diagnostic(1 byte)"""
        s_initialize("BFD_FUZZ_VERSION_DIAG")

        with s_block("BFD_HEADER"):
            s_random(
                "VersionDiag", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_bytes(
                value=((BFD_STATE_UP << 6)).to_bytes(1, "big"),
                name="StateFlags",
                fuzzable=False,
            )
            s_bytes(value=(3).to_bytes(1, "big"), name="DetectMult", fuzzable=False)
            s_bytes(
                value=(BFD_MIN_PACKET_LEN).to_bytes(1, "big"),
                name="Length",
                fuzzable=False,
            )
            s_bytes(
                value=self.my_discriminator.to_bytes(4, "big"),
                name="MyDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=self.server_my_disc.to_bytes(4, "big"),
                name="YourDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="DesiredMinTxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="RequiredMinRxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(0).to_bytes(4, "big"),
                name="RequiredMinEchoRxInterval",
                fuzzable=False,
            )

        self.session.connect(s_get("BFD_FUZZ_VERSION_DIAG"))
        self.session.fuzz()

    def fuzz_state_flags(self):
        """Fuzzing State + Flags (1 byte) with correct packet structure"""
        s_initialize("BFD_FUZZ_STATE_FLAGS")

        with s_block("BFD_HEADER"):
            s_bytes(
                value=((BFD_VERSION << 5) | BFD_DIAG_NO_DIAG).to_bytes(1, "big"),
                name="VersionDiag",
                fuzzable=False,
            )
            s_random(
                "StateFlags", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_bytes(value=(3).to_bytes(1, "big"), name="DetectMult", fuzzable=False)
            s_bytes(
                value=(BFD_MIN_PACKET_LEN).to_bytes(1, "big"),
                name="Length",
                fuzzable=False,
            )
            s_bytes(
                value=self.my_discriminator.to_bytes(4, "big"),
                name="MyDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=self.server_my_disc.to_bytes(4, "big"),
                name="YourDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="DesiredMinTxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="RequiredMinRxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(0).to_bytes(4, "big"),
                name="RequiredMinEchoRxInterval",
                fuzzable=False,
            )

        self.session.connect(s_get("BFD_FUZZ_STATE_FLAGS"))
        self.session.fuzz()

    def fuzz_detect_mult(self):
        """Fuzzing Detect Multiplier (1 byte)"""
        s_initialize("BFD_FUZZ_DETECT_MULT")

        with s_block("BFD_HEADER"):
            s_bytes(
                value=((BFD_VERSION << 5) | BFD_DIAG_NO_DIAG).to_bytes(1, "big"),
                name="VersionDiag",
                fuzzable=False,
            )
            s_bytes(
                value=((BFD_STATE_UP << 6)).to_bytes(1, "big"),
                name="StateFlags",
                fuzzable=False,
            )
            s_random(
                "DetectMult", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_bytes(
                value=(BFD_MIN_PACKET_LEN).to_bytes(1, "big"),
                name="Length",
                fuzzable=False,
            )
            s_bytes(
                value=self.my_discriminator.to_bytes(4, "big"),
                name="MyDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=self.server_my_disc.to_bytes(4, "big"),
                name="YourDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="DesiredMinTxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="RequiredMinRxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(0).to_bytes(4, "big"),
                name="RequiredMinEchoRxInterval",
                fuzzable=False,
            )

        self.session.connect(s_get("BFD_FUZZ_DETECT_MULT"))
        self.session.fuzz()

    def fuzz_length(self):
        """Fuzzing Length (1 byte)"""
        s_initialize("BFD_FUZZ_LENGTH")

        with s_block("BFD_HEADER"):
            s_bytes(
                value=((BFD_VERSION << 5) | BFD_DIAG_NO_DIAG).to_bytes(1, "big"),
                name="VersionDiag",
                fuzzable=False,
            )
            s_bytes(
                value=((BFD_STATE_UP << 6)).to_bytes(1, "big"),
                name="StateFlags",
                fuzzable=False,
            )
            s_bytes(value=(3).to_bytes(1, "big"), name="DetectMult", fuzzable=False)
            s_random("Length", min_length=1, max_length=1, num_mutations=self.max_tests)
            s_bytes(
                value=self.my_discriminator.to_bytes(4, "big"),
                name="MyDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=self.server_my_disc.to_bytes(4, "big"),
                name="YourDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="DesiredMinTxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="RequiredMinRxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(0).to_bytes(4, "big"),
                name="RequiredMinEchoRxInterval",
                fuzzable=False,
            )

        self.session.connect(s_get("BFD_FUZZ_LENGTH"))
        self.session.fuzz()

    def fuzz_my_discriminator(self):
        """Fuzzing My Discriminator (4 bytes)"""
        s_initialize("BFD_FUZZ_MY_DISCRIMINATOR")

        with s_block("BFD_PAYLOAD"):
            s_bytes(
                value=((BFD_VERSION << 5) | BFD_DIAG_NO_DIAG).to_bytes(1, "big"),
                name="VersionDiag",
                fuzzable=False,
            )
            s_bytes(
                value=((BFD_STATE_UP << 6)).to_bytes(1, "big"),
                name="StateFlags",
                fuzzable=False,
            )
            s_bytes(value=(3).to_bytes(1, "big"), name="DetectMult", fuzzable=False)
            s_bytes(
                value=(BFD_MIN_PACKET_LEN).to_bytes(1, "big"),
                name="Length",
                fuzzable=False,
            )
            s_random(
                "MyDiscriminator",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )
            s_bytes(
                value=self.server_my_disc.to_bytes(4, "big"),
                name="YourDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="DesiredMinTxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="RequiredMinRxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(0).to_bytes(4, "big"),
                name="RequiredMinEchoRxInterval",
                fuzzable=False,
            )

        self.session.connect(s_get("BFD_FUZZ_MY_DISCRIMINATOR"))
        self.session.fuzz()

    def fuzz_your_discriminator(self):
        """Fuzzing Your Discriminator (4 bytes)"""
        s_initialize("BFD_FUZZ_YOUR_DISCRIMINATOR")

        with s_block("BFD_PAYLOAD"):
            s_bytes(
                value=((BFD_VERSION << 5) | BFD_DIAG_NO_DIAG).to_bytes(1, "big"),
                name="VersionDiag",
                fuzzable=False,
            )
            s_bytes(
                value=((BFD_STATE_UP << 6)).to_bytes(1, "big"),
                name="StateFlags",
                fuzzable=False,
            )
            s_bytes(value=(3).to_bytes(1, "big"), name="DetectMult", fuzzable=False)
            s_bytes(
                value=(BFD_MIN_PACKET_LEN).to_bytes(1, "big"),
                name="Length",
                fuzzable=False,
            )
            s_bytes(
                value=self.my_discriminator.to_bytes(4, "big"),
                name="MyDiscriminator",
                fuzzable=False,
            )
            s_random(
                "YourDiscriminator",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="DesiredMinTxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(1000000).to_bytes(4, "big"),
                name="RequiredMinRxInterval",
                fuzzable=False,
            )
            s_bytes(
                value=(0).to_bytes(4, "big"),
                name="RequiredMinEchoRxInterval",
                fuzzable=False,
            )

        self.session.connect(s_get("BFD_FUZZ_YOUR_DISCRIMINATOR"))
        self.session.fuzz()

    def fuzz_intervals(self):
        """Fuzzing all intervals"""
        s_initialize("BFD_FUZZ_INTERVALS")

        with s_block("BFD_PAYLOAD"):
            s_bytes(
                value=((BFD_VERSION << 5) | BFD_DIAG_NO_DIAG).to_bytes(1, "big"),
                name="VersionDiag",
                fuzzable=False,
            )
            s_bytes(
                value=((BFD_STATE_UP << 6)).to_bytes(1, "big"),
                name="StateFlags",
                fuzzable=False,
            )
            s_bytes(value=(3).to_bytes(1, "big"), name="DetectMult", fuzzable=False)
            s_bytes(
                value=(BFD_MIN_PACKET_LEN).to_bytes(1, "big"),
                name="Length",
                fuzzable=False,
            )
            s_bytes(
                value=self.my_discriminator.to_bytes(4, "big"),
                name="MyDiscriminator",
                fuzzable=False,
            )
            s_bytes(
                value=self.server_my_disc.to_bytes(4, "big"),
                name="YourDiscriminator",
                fuzzable=False,
            )
            s_random(
                "DesiredMinTxInterval",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )
            s_random(
                "RequiredMinRxInterval",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )
            s_random(
                "RequiredMinEchoRxInterval",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )

        self.session.connect(s_get("BFD_FUZZ_INTERVALS"))
        self.session.fuzz()

    def fuzz_all_fields(self):
        """Fuzzing all fields"""
        s_initialize("BFD_FUZZ_ALL_FIELDS")

        with s_block("BFD_HEADER"):
            s_random(
                "VersionDiag", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_random(
                "StateFlags", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_random(
                "DetectMult", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_random("Length", min_length=1, max_length=1, num_mutations=self.max_tests)
            s_random(
                "MyDiscriminator",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )
            s_random(
                "YourDiscriminator",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )
            s_random(
                "DesiredMinTxInterval",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )
            s_random(
                "RequiredMinRxInterval",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )
            s_random(
                "RequiredMinEchoRxInterval",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )

        self.session.connect(s_get("BFD_FUZZ_ALL_FIELDS"))
        self.session.fuzz()
