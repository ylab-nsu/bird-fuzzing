import json
import random
import socket

import paramiko
from boofuzz import *

from app.custom_logger import CustomFuzzLogger

# Константы для протокола BFD
BFD_MIN_PACKET_LEN = 24
BFD_VERSION = 1
BFD_DIAG_NO_DIAG = 0
BFD_STATE_ADMIN_DOWN = 0
BFD_STATE_DOWN = 1
BFD_STATE_INIT = 2
BFD_STATE_UP = 3


class CustomUDPSocketConnection(UDPSocketConnection):
    def __init__(self, host, port, ttl=255, tos=0xc0, **kwargs):
        super().__init__(host=host, port=port, **kwargs)
        self.ttl = ttl
        self.tos = tos

    def open(self):
        super().open()
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, self.tos)


class BFDFuzzTest:
    def __init__(self, config_file=None, max_tests=1000):
        with open(config_file, 'r') as f:
            config = json.load(f)
        self.config_file = config_file
        self.max_tests = max_tests
        self.BIRD_USER = 'root'
        self.BIRD_IP = config['BIRD_BGP_ID']
        self.BIRD_PASSWORD = 'password'

        self.log_file = "logs.txt"
        self.logger = CustomFuzzLogger(self.log_file)

        self.session = Session(
            target=Target(connection=CustomUDPSocketConnection("192.168.100.10", 3784, ttl=255, tos=0xc0)),
            index_start=1,
            index_end=self.max_tests,
            web_port=None,
            post_test_case_callbacks=[self.print_new_logs, self.restart_uplink],
            fuzz_loggers=[self.logger]  # Используем кастомный логгер
        )

    @staticmethod
    def ip_str_to_bytes(ip):
        """Transformation IP-address to bytes."""
        return int.from_bytes(socket.inet_aton(ip), 'big')

    def get_ssh_client(self):
        """ Создаем и возвращаем SSH-клиент для подключения к контейнеру """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Доверяемся неизвестному ключу хоста
            client.connect(self.BIRD_IP, username=self.BIRD_USER, password=self.BIRD_PASSWORD)
            return client
        except Exception as e:
            print(f"Failed to connect to SSH: {e}")
            return None

    def print_new_logs(self, target=None, fuzz_data_logger=None, session=None, sock=None):
        """Function for printing logs bird through SSH"""
        try:
            # Подключаемся по SSH
            client = self.get_ssh_client()
            if client:
                stdin, stdout, stderr = client.exec_command(
                    'tail -n1 /var/log/bird.log')  # Выполняем команду в контейнере
                log_entry = stdout.read().decode().strip()  # Получаем строку из вывода
                if log_entry:  # Если строка не пуста, выводим её
                    # Открываем файл для дозаписи и записываем лог
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(log_entry + "\n")
                client.close()  # Закрываем соединение
        except Exception as e:
            print(f"Failed to read logs of container with bird via SSH: {e}")

    def restart_uplink(self, target=None, fuzz_data_logger=None, session=None, sock=None):
        """Function for restarting BGP protocol in container with bird via SSH"""
        try:
            # Подключаемся по SSH
            client = self.get_ssh_client()
            if client:
                stdin, stdout, stderr = client.exec_command(
                    f'birdc restart bfd1')  # Выполняем команду в контейнере
                # result = stdout.read().decode().strip()
                # if result:
                # print(f"Restart result: {result}")
                client.close()  # Закрываем соединение
        except Exception as e:
            print(f"Failed to restart BGP_PROTO_NAME via SSH: {e}")

    @staticmethod
    def _add_base_fields(block_name):
        """Добавляет базовые поля BFD пакета с корректными значениями."""
        with s_block(block_name):
            # Version + Diag (1 byte)
            s_byte(value=(BFD_VERSION << 5) | BFD_DIAG_NO_DIAG, name="VersionDiag", fuzzable=False)
            # State + Flags (1 byte)
            s_byte(value=(BFD_STATE_UP << 6), name="StateFlags", fuzzable=False)
            # Detect Mult (1 byte)
            s_byte(value=3, name="DetectMult", fuzzable=False)
            # Length (1 byte)
            s_byte(value=BFD_MIN_PACKET_LEN, name="Length", fuzzable=False)
            # My Discriminator (4 bytes)
            s_dword(value=0x12345678, name="MyDiscriminator", fuzzable=False)
            # Your Discriminator (4 bytes)
            s_dword(value=0x9d3eff01, name="YourDiscriminator", fuzzable=False)
            # Intervals (4 bytes each)
            s_dword(value=1000000, name="DesiredMinTxInterval", fuzzable=False)
            s_dword(value=1000000, name="RequiredMinRxInterval", fuzzable=False)
            s_dword(value=0, name="RequiredMinEchoRxInterval", fuzzable=False)

    def _add_random_field(self, name, size, max_mutations=None):
        """Добавляет случайное поле с указанным размером."""
        if max_mutations is None:
            max_mutations = self.max_tests

        if size == 1:
            s_random(name, min_length=1, max_length=1, num_mutations=max_mutations)
        elif size == 4:
            s_random(name, min_length=4, max_length=4, num_mutations=max_mutations)
        else:
            raise ValueError(f"Unsupported field size: {size}")

    def fuzz_version_diag(self):
        """Фуззинг поля Version + Diagnostic (1 байт)."""
        s_initialize("BFD_FUZZ_VERSION_DIAG")
        with s_block("BFD_HEADER"):
            self._add_random_field("VersionDiag", 1)
            self._add_base_fields("BFD_BASE_FIELDS")

        self.session.connect(s_get("BFD_FUZZ_VERSION_DIAG"))
        self.session.fuzz()

    def fuzz_state_flags(self):
        """Фуззинг поля State + Flags (1 байт)."""
        s_initialize("BFD_FUZZ_STATE_FLAGS")
        with s_block("BFD_HEADER"):
            s_byte((BFD_VERSION << 5) | BFD_DIAG_NO_DIAG, name="VersionDiag", fuzzable=False)
            self._add_random_field("StateFlags", 1)
            # Остальные базовые поля
            s_byte(3, name="DetectMult", fuzzable=False)
            s_byte(BFD_MIN_PACKET_LEN, name="Length", fuzzable=False)
            self._add_base_fields("BFD_BASE_FIELDS")

        self.session.connect(s_get("BFD_FUZZ_STATE_FLAGS"))
        self.session.fuzz()

    def fuzz_detect_mult(self):
        """Фуззинг поля Detect Multiplier (1 байт)."""
        s_initialize("BFD_FUZZ_DETECT_MULT")
        with s_block("BFD_HEADER"):
            self._add_base_fields("BFD_BASE_FIELDS")
            self._add_random_field("DetectMult", 1)

        self.session.connect(s_get("BFD_FUZZ_DETECT_MULT"))
        self.session.fuzz()

    def fuzz_length(self):
        """Фуззинг поля Length (1 байт)."""
        s_initialize("BFD_FUZZ_LENGTH")
        with s_block("BFD_HEADER"):
            self._add_base_fields("BFD_BASE_FIELDS")
            self._add_random_field("Length", 1)

        self.session.connect(s_get("BFD_FUZZ_LENGTH"))
        self.session.fuzz()

    def fuzz_my_discriminator(self):
        """Фуззинг поля My Discriminator (4 байта)."""
        s_initialize("BFD_FUZZ_MY_DISCRIMINATOR")
        with s_block("BFD_PAYLOAD"):
            self._add_base_fields("BFD_BASE_FIELDS")
            self._add_random_field("MyDiscriminator", 4)

        self.session.connect(s_get("BFD_FUZZ_MY_DISCRIMINATOR"))
        self.session.fuzz()

    def fuzz_your_discriminator(self):
        """Фуззинг поля Your Discriminator (4 байта)."""
        s_initialize("BFD_FUZZ_YOUR_DISCRIMINATOR")
        with s_block("BFD_PAYLOAD"):
            self._add_base_fields("BFD_BASE_FIELDS")
            self._add_random_field("YourDiscriminator", 4)

        self.session.connect(s_get("BFD_FUZZ_YOUR_DISCRIMINATOR"))
        self.session.fuzz()

    def fuzz_intervals(self):
        """Фуззинг всех интервалов одновременно."""
        s_initialize("BFD_FUZZ_INTERVALS")
        with s_block("BFD_PAYLOAD"):
            self._add_base_fields("BFD_BASE_FIELDS")
            self._add_random_field("DesiredMinTxInterval", 4)
            self._add_random_field("RequiredMinRxInterval", 4)
            self._add_random_field("RequiredMinEchoRxInterval", 4)

        self.session.connect(s_get("BFD_FUZZ_INTERVALS"))
        self.session.fuzz()

    def fuzz_all_fields(self):
        """Фуззинг всех полей одновременно."""
        s_initialize("BFD_FUZZ_ALL_FIELDS")
        with s_block("BFD_HEADER"):
            self._add_random_field("VersionDiag", 1)
            self._add_random_field("StateFlags", 1)
            self._add_random_field("DetectMult", 1)
            self._add_random_field("Length", 1)
            self._add_random_field("MyDiscriminator", 4)
            self._add_random_field("YourDiscriminator", 4)
            self._add_random_field("DesiredMinTxInterval", 4)
            self._add_random_field("RequiredMinRxInterval", 4)
            self._add_random_field("RequiredMinEchoRxInterval", 4)

        self.session.connect(s_get("BFD_FUZZ_ALL_FIELDS"))
        self.session.fuzz()