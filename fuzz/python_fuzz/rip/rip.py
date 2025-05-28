import json
import socket
import paramiko
from boofuzz import *
from custom_logger import CustomFuzzLogger

# Constants for RIP
RIP_PORT = 520
RIP_HEADER_LEN = 4
RIP_ENTRY_LEN = 20
RIP_COMMAND_REQUEST = 1
RIP_COMMAND_RESPONSE = 2
RIP_VERSION = 2


class CustomUDPSocketConnection(UDPSocketConnection):
    def __init__(self, host, port, ttl=1, tos=0xC0, **kwargs):
        super().__init__(host=host, port=port, **kwargs)
        self.ttl = ttl
        self.tos = tos
        self.src_port = RIP_PORT

    def open(self):
        super().open()
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, self.tos)
        self._sock.bind(("", self.src_port))


class RIPFuzzTest:
    def __init__(self, config_file=None, max_tests=1000):
        with open(config_file, "r") as f:
            config = json.load(f)

        self.config_file = config_file
        self.max_tests = max_tests
        self.BIRD_USER = "root"
        self.BIRD_IP = config["BIRD_BGP_ID"]
        self.BIRD_PASSWORD = "password"
        self.log_file = "rip_fuzz_logs.txt"
        self.logger = CustomFuzzLogger(self.log_file)

        self.session = Session(
            target=Target(
                connection=CustomUDPSocketConnection(
                    "192.168.100.10", RIP_PORT, ttl=1, tos=0xC0
                )
            ),
            index_start=1,
            index_end=self.max_tests,
            web_port=None,
            post_test_case_callbacks=[self.print_new_logs, self.restart_rip],
            fuzz_loggers=[self.logger],
        )

    def get_ssh_client(self):
        """Make and return SSH-client for connection to Docker container"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.BIRD_IP, username=self.BIRD_USER, password=self.BIRD_PASSWORD
            )
            return client
        except Exception as e:
            print(f"SSH Connection Error: {e}")
            return None

    def print_new_logs(
        self, target=None, fuzz_data_logger=None, session=None, sock=None
    ):
        """Function for printing logs bird through SSH"""
        try:
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

    def restart_rip(self, target=None, fuzz_data_logger=None, session=None, sock=None):
        """Restart RIP protocol"""
        try:
            client = self.get_ssh_client()
            if client:
                stdin, stdout, stderr = client.exec_command("birdc restart rip1")
                client.close()
        except Exception as e:
            print(f"Protocol Restart Error: {e}")

    def fuzz_command_version(self):
        """Fuzzing Command and Version"""
        s_initialize("RIP_FUZZ_CMD_VER")

        with s_block("RIP_Header"):
            s_random(
                name="command", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_random(
                name="version", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_static(b"\x00\x00", name="zero_field")  # Фиксированные 2 нулевых байта

        with s_block("RIP_Entry"):
            s_static(b"\x00\x02", name="AFI")  # 2 байта (IPv4)
            s_static(b"\x00\x00", name="Route_Tag")  # 2 байта
            s_static(b"\xc0\xa8\x01\x00", name="IP")  # 4 байта (192.168.1.0)
            s_static(b"\xff\xff\xff\x00", name="Mask")  # 4 байта (/24)
            s_static(b"\x00\x00\x00\x00", name="Next_Hop")  # 4 байта (Next hop)
            s_static(b"\x00\x00\x00\x01", name="Metric")  # 4 байта (Metric = 1)

        self.session.connect(s_get("RIP_FUZZ_CMD_VER"))
        self.session.fuzz()

    def fuzz_authentication(self):
        """Fuzzing authentication"""
        s_initialize("RIP_FUZZ_AUTH_VALID_CASES")

        with s_block("RIP_Header"):
            s_static(RIP_COMMAND_RESPONSE.to_bytes(1, "big"), name="command")
            s_static(RIP_VERSION.to_bytes(1, "big"), name="version")
            s_static(b"\x00\x00", name="zero_field")

        with s_block("Simple_Password_Auth"):
            s_static(b"\xff\xff", name="Auth_AFI")
            s_static(b"\x00\x02", name="Auth_Type_Simple")  # Тип 2 - простой пароль
            s_random(
                "Simple_Password",
                min_length=16,
                max_length=16,
                num_mutations=self.max_tests,
            )

        with s_block("MD5_Auth"):
            s_static(b"\xff\xff", name="Auth_AFI")
            s_static(b"\x00\x03", name="Auth_Type_MD5")  # Тип 3 - MD5
            s_random(
                "MD5_Hash", min_length=16, max_length=16, num_mutations=self.max_tests
            )

        with s_block("Invalid_Auth_Types"):
            s_static(b"\xff\xff", name="Auth_AFI")
            s_random(
                "Invalid_Auth_Type",
                min_length=2,
                max_length=2,
                num_mutations=self.max_tests,
            )
            s_random(
                "Auth_Data", min_length=16, max_length=16, num_mutations=self.max_tests
            )

        self.session.connect(s_get("RIP_FUZZ_AUTH_VALID_CASES"))
        self.session.fuzz()

    def fuzz_afi(self):
        """Fuzzing AFI in RIP-entries"""
        s_initialize("RIP_FUZZ_AFI")

        with s_block("RIP_Header"):
            s_static(RIP_COMMAND_RESPONSE.to_bytes(1, "big"), name="command")
            s_static(RIP_VERSION.to_bytes(1, "big"), name="version")
            s_static(b"\x00\x00", name="zero_field")

        with s_block("RIP_Entry"):
            s_random(
                name="AFI", min_length=2, max_length=2, num_mutations=self.max_tests
            )
            s_static(b"\x00\x00", name="Route_Tag")
            s_static(b"\xc0\xa8\x01\x00", name="IP")
            s_static(b"\xff\xff\xff\x00", name="Mask")
            s_static(b"\x00\x00\x00\x00", name="Next_Hop")
            s_static(b"\x00\x00\x00\x01", name="Metric")

        self.session.connect(s_get("RIP_FUZZ_AFI"))
        self.session.fuzz()

    def fuzz_ip_address(self):
        """Fuzzing IP-address"""
        s_initialize("RIP_FUZZ_IP")

        with s_block("RIP_Header"):
            s_static(RIP_COMMAND_RESPONSE.to_bytes(1, "big"), name="command")
            s_static(RIP_VERSION.to_bytes(1, "big"), name="version")
            s_static(b"\x00\x00", name="zero_field")

        with s_block("RIP_Entry"):
            s_static(b"\x00\x02", name="AFI")
            s_static(b"\x00\x00", name="Route_Tag")
            s_random(
                name="IP", min_length=4, max_length=4, num_mutations=self.max_tests
            )
            s_static(b"\xff\xff\xff\x00", name="Mask")
            s_static(b"\x00\x00\x00\x00", name="Next_Hop")
            s_static(b"\x00\x00\x00\x01", name="Metric")

        self.session.connect(s_get("RIP_FUZZ_IP"))
        self.session.fuzz()

    def fuzz_mask(self):
        """Fuzzing mask"""
        s_initialize("RIP_FUZZ_MASK")

        with s_block("RIP_Header"):
            s_static(RIP_COMMAND_RESPONSE.to_bytes(1, "big"), name="command")
            s_static(RIP_VERSION.to_bytes(1, "big"), name="version")
            s_static(b"\x00\x00", name="zero_field")

        with s_block("RIP_Entry"):
            s_static(b"\x00\x02", name="AFI")
            s_static(b"\x00\x00", name="Route_Tag")
            s_static(b"\xc0\xa8\x01\x00", name="IP")
            s_random(
                name="Mask", min_length=4, max_length=4, num_mutations=self.max_tests
            )
            s_static(b"\x00\x00\x00\x00", name="Next_Hop")
            s_static(b"\x00\x00\x00\x01", name="Metric")

        self.session.connect(s_get("RIP_FUZZ_MASK"))
        self.session.fuzz()

    def fuzz_metric(self):
        """Fuzzing Metric"""
        s_initialize("RIP_FUZZ_METRIC")

        with s_block("RIP_Header"):
            s_static(RIP_COMMAND_RESPONSE.to_bytes(1, "big"), name="command")
            s_static(RIP_VERSION.to_bytes(1, "big"), name="version")
            s_static(b"\x00\x00", name="zero_field")

        with s_block(f"RIP_Entry"):
            s_static(b"\x00\x02", name="AFI")
            s_static(b"\x00\x00", name="Route_Tag")
            s_static(b"\xc0\xa8\x01\x00", name="IP")
            s_static(b"\xff\xff\xff\x00", name="Mask")
            s_static(b"\x00\x00\x00\x00", name="Next_Hop")
            s_random(
                name="Metric", min_length=4, max_length=4, num_mutations=self.max_tests
            )

        self.session.connect(s_get("RIP_FUZZ_METRIC"))
        self.session.fuzz()

    def fuzz_route_entries(self):
        """Fuzzing all fields in entries"""
        s_initialize("RIP_FUZZ_ENTRIES")

        with s_block("RIP_Header"):
            s_static(RIP_COMMAND_RESPONSE.to_bytes(1, "big"), name="command")
            s_static(RIP_VERSION.to_bytes(1, "big"), name="version")
            s_static(b"\x00\x00", name="zero_field")

        with s_block("RIP_Entry"):
            s_random(
                name="AFI", min_length=2, max_length=2, num_mutations=self.max_tests
            )
            s_random(
                name="Route_Tag",
                min_length=2,
                max_length=2,
                num_mutations=self.max_tests,
            )
            s_random(
                name="IP", min_length=4, max_length=4, num_mutations=self.max_tests
            )
            s_random(
                name="Mask", min_length=4, max_length=4, num_mutations=self.max_tests
            )
            s_random(
                name="Next_Hop",
                min_length=4,
                max_length=4,
                num_mutations=self.max_tests,
            )
            s_random(
                name="Metric", min_length=4, max_length=4, num_mutations=self.max_tests
            )

        self.session.connect(s_get("RIP_FUZZ_ENTRIES"))
        self.session.fuzz()

    def fuzz_malformed_packets(self):
        """Fuzzing full packet"""
        s_initialize("RIP_FUZZ_MALFORMED")

        s_random(name="full_packet", num_mutations=self.max_tests)

        self.session.connect(s_get("RIP_FUZZ_MALFORMED"))
        self.session.fuzz()
