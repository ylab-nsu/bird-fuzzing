import json
import socket
import paramiko
from boofuzz import *
from app.custom_logger import CustomFuzzLogger

# Константы для протокола RIP
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

    def open(self):
        super().open()
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, self.tos)


class RIPFuzzTest:
    def __init__(self, config_file=None, max_tests=1000):
        with open(config_file, "r") as f:
            config = json.load(f)

        self.config_file = config_file
        self.max_tests = max_tests
        self.BIRD_USER = "root"
        self.BIRD_IP = config["BIRD_RIP_ID"]
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
                    "tail -n5 /var/log/bird.log"
                )
                logs = stdout.read().decode().strip()
                if logs:
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(f"\n[Bird Logs]\n{logs}\n")
                client.close()
        except Exception as e:
            print(f"Log Read Error: {e}")

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
        """Фаззинг полей Command и Version"""
        s_initialize("RIP_FUZZ_CMD_VER")

        with s_block("RIP_Header"):
            s_random(
                "command", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_random(
                "version", min_length=1, max_length=1, num_mutations=self.max_tests
            )
            s_static(b"\x00\x00", name="zero_field")  # 2 нулевых байта

        # Добавляем одну валидную запись
        with s_block("RIP_Entry"):
            s_static(b"\x00\x02", name="AFI")  # IPv4
            s_static(b"\x00\x00", name="Route_Tag")  # Тег маршрута
            s_static(b"\xc0\xa8\x01\x00", name="IP")  # 192.168.1.0
            s_static(b"\xff\xff\xff\x00", name="Mask")  # /24
            s_static(b"\x00\x00\x00\x00", name="Next_Hop")
            s_static(b"\x00\x00\x00\x01", name="Metric")  # Metric=1

        self.session.connect(s_get("RIP_FUZZ_CMD_VER"))
        self.session.fuzz()

    def fuzz_authentication(self):
        """Фаззинг аутентификации"""
        s_initialize("RIP_FUZZ_AUTH")

        with s_block("RIP_Header"):
            s_static(RIP_COMMAND_RESPONSE.to_bytes(1, "big"), name="command")
            s_static(RIP_VERSION.to_bytes(1, "big"), name="version")
            s_static(b"\x00\x00", name="zero_field")

        with s_block("Auth_Entry"):
            s_static(b"\xff\xff", name="Auth_AFI")  # 0xFFFF для аутентификации
            s_random("Auth_Type", min_length=2, max_length=2, num_mutations=10)
            s_random(
                "Auth_Data", min_length=16, max_length=16, num_mutations=self.max_tests
            )

        self.session.connect(s_get("RIP_FUZZ_AUTH"))
        self.session.fuzz()

    def fuzz_metric(self):
        """Фаззинг метрик в RIP-записях"""
        s_initialize("RIP_FUZZ_METRIC")

        with s_block("RIP_Header"):
            s_static(RIP_COMMAND_RESPONSE.to_bytes(1, "big"), name="command")
            s_static(RIP_VERSION.to_bytes(1, "big"), name="version")
            s_static(b"\x00\x00", name="zero_field")

        # Добавляем 25 записей (максимум для одного пакета)
        for i in range(25):
            with s_block(f"RIP_Entry_{i}"):
                s_static(b"\x00\x02", name="AFI")
                s_static(b"\x00\x00", name="Route_Tag")
                s_static(b"\xc0\xa8\x01\x00")
                s_static(b"\xff\xff\xff\x00", name="Subnet_Mask")
                s_static(b"\x00\x00\x00\x00", name="Next_Hop")
                s_random(
                    "Metric", min_length=4, max_length=4, num_mutations=self.max_tests
                )

        self.session.connect(s_get("RIP_FUZZ_METRIC"))
        self.session.fuzz()

    def fuzz_route_entries(self):
        """Фаззинг всех полей в RIP-записях"""
        s_initialize("RIP_FUZZ_ENTRIES")

        with s_block("RIP_Header"):
            s_static(RIP_COMMAND_RESPONSE.to_bytes(1, "big"), name="command")
            s_static(RIP_VERSION.to_bytes(1, "big"), name="version")
            s_static(b"\x00\x00", name="zero_field")

        with s_block("RIP_Entry"):
            s_random("AFI", min_length=2, max_length=2, num_mutations=100)
            s_random("Route_Tag", min_length=2, max_length=2, num_mutations=100)
            s_random("IP", min_length=4, max_length=4, num_mutations=100)
            s_random("Mask", min_length=4, max_length=4, num_mutations=100)
            s_random("Next_Hop", min_length=4, max_length=4, num_mutations=100)
            s_random("Metric", min_length=4, max_length=4, num_mutations=100)

        self.session.connect(s_get("RIP_FUZZ_ENTRIES"))
        self.session.fuzz()

    def fuzz_malformed_packets(self):
        """Генерация полностью искаженных пакетов"""
        s_initialize("RIP_FUZZ_MALFORMED")
        s_random(
            "full_packet", min_length=4, max_length=512, num_mutations=self.max_tests
        )
        self.session.connect(s_get("RIP_FUZZ_MALFORMED"))
        self.session.fuzz()
