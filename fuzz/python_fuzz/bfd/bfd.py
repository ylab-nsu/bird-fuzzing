import random
import socket
from boofuzz import *

# Константы для протокола BFD
BFD_MIN_PACKET_LEN = 24  # минимальная длина BFD Control Packet
BFD_VERSION = 1  # стандартная версия BFD (3 бита)
BFD_DIAG_NO_DIAG = 0  # стандартное значение поля диагностики (5 бит, например, 0)
BFD_STATE_ADMIN_DOWN = 0  # пример состояния
BFD_STATE_DOWN = 1
BFD_STATE_INIT = 2
BFD_STATE_UP = 3

class CustomUDPSocketConnection(UDPSocketConnection):
    def __init__(self, host, port, ttl=255, tos=0xc0, **kwargs):
        super().__init__(host=host, port=port, **kwargs)
        self.ttl = ttl
        self.tos = tos

    def open(self):
        # Создаем сокет через родительский класс
        super().open()
        # Настраиваем параметры сокета
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, self.tos)


class BFDFuzzTest:
    def __init__(self, config_file, max_tests=100):
        self.config_file = config_file
        self.max_tests = max_tests
        self.session = Session(
            target=Target(connection=CustomUDPSocketConnection("192.168.100.10", 3784, ttl=255, tos=0xc0))
        )

    @staticmethod
    def initialize_bfd_header(block_name):
        """
        Инициализация базовой части BFD Control Packet:
        Поле 1: Vers (3 бита) и Diag (5 бит)
        Поле 2: State (2 бита) и Flags (6 бит) – здесь будем тестировать состояние,
                 флаги можно оставить статичными в данном примере.
        """
        with s_block(block_name):
            # Поле Vers + Diag (1 байт)
            # Здесь упаковываем версию и диагностику в один байт:
            # Например: (BFD_VERSION << 5) | BFD_DIAG_NO_DIAG
            default_first_byte = (BFD_VERSION << 5) | BFD_DIAG_NO_DIAG
            s_byte(value=default_first_byte, endian=BIG_ENDIAN, name="VersionDiag", fuzzable=False)
            # Поле State + Flags (1 байт)
            # Выставляем состояние + фиксированные флаги (например, 0)
            default_second_byte = (BFD_STATE_UP << 6)  # состояние занято в старших двух битах
            s_byte(value=default_second_byte, endian=BIG_ENDIAN, name="StateFlags", fuzzable=False)
            # Поле Detect Mult (1 байт)
            s_byte(value=3, endian=BIG_ENDIAN, name="Detect Mult", fuzzable=False)
            # Поле Length (1 байт) – минимальная длина пакета
            s_byte(value=BFD_MIN_PACKET_LEN, endian=BIG_ENDIAN, name="Length", fuzzable=False)

    def fuzz_bfd_control_packet(self):
        """
        Фуззинг BFD Control Packet.
        Тестируем:
         - Версию и диагностику (объединённое в один байт поле)
         - Состояние и флаги (объединённое в один байт поле)
         - Detect Mult – множитель обнаружения
         - Length – длина пакета
         - My Discriminator, Your Discriminator
         - Интервалы: Desired Min TX, Required Min RX, Required Min Echo RX
        """
        s_initialize("bfd_control")
        with s_block("BFD"):
            self.initialize_bfd_header("Header")
            # My Discriminator: 4 байта
            s_dword(value=0x12345678, endian=BIG_ENDIAN, name="My Discriminator", fuzzable=True)
            # Your Discriminator: 4 байта
            s_dword(value=0x91195d73, endian=BIG_ENDIAN, name="Your Discriminator", fuzzable=True)
            # Desired Min TX Interval: 4 байта (в микросекундах)
            s_dword(value=1000000, endian=BIG_ENDIAN, name="Desired Min TX Interval", fuzzable=True)
            # Required Min RX Interval: 4 байта (в микросекундах)
            s_dword(value=1000000, endian=BIG_ENDIAN, name="Required Min RX Interval", fuzzable=True)
            # Required Min Echo RX Interval: 4 байта (в микросекундах)
            s_dword(value=0, endian=BIG_ENDIAN, name="Required Min Echo RX Interval", fuzzable=True)

        self.session.connect(s_get("bfd_control"))
        self.session.fuzz("bfd_control")

    def fuzz_bfd_version_field(self):
        """
        Фуззинг поля Version+Diag (1 байт), чтобы проверить крайние значения и
        некорректные комбинации.
        """
        s_initialize("bfd_version")
        with s_block("BFD"):
            # Фуззим поле VersionDiag
            # Минимум 1 байт, максимум 1 байт, большое количество мутаций
            s_random(value='', min_length=1, max_length=1, num_mutations=100, name="VersionDiag", fuzzable=True)
            # Остальные поля фиксированные
            s_static(value=b"\xC0", name="StateFlags")  # например, фиксированное состояние UP (0xC0)
            s_static(value=b"\x03", name="DetectMult")
            s_static(value=bytes([BFD_MIN_PACKET_LEN]), name="Length")
            s_dword(value=0x12345678, endian=BIG_ENDIAN, name="My Discriminator", fuzzable=False)
            s_dword(value=0x9d3eff01, endian=BIG_ENDIAN, name="Your Discriminator", fuzzable=False)
            s_dword(value=1000000, endian=BIG_ENDIAN, name="Desired Min TX Interval", fuzzable=False)
            s_dword(value=1000000, endian=BIG_ENDIAN, name="Required Min RX Interval", fuzzable=False)
            s_dword(value=0, endian=BIG_ENDIAN, name="Required Min Echo RX Interval", fuzzable=False)

        self.session.connect(s_get("bfd_version"))
        self.session.fuzz("bfd_version")

    def fuzz_bfd_discriminator_fields(self):
        """
        Фуззинг полей My Discriminator и Your Discriminator для проверки
        обработки некорректных значений.
        """
        s_initialize("bfd_discriminators")
        with s_block("BFD"):
            self.initialize_bfd_header("Header")
            # Фиксируем остальные поля
            # My Discriminator - фуззинг
            s_random(value='', min_length=4, max_length=4, num_mutations=100000, name="My Discriminator", fuzzable=True)
            # Your Discriminator - фуззинг
            s_random(value='', min_length=4, max_length=4, num_mutations=100000, name="Your Discriminator",
                     fuzzable=True)
            # Остальные интервалы фиксированные
            s_dword(value=1000000, endian=BIG_ENDIAN, name="Desired Min TX Interval", fuzzable=False)
            s_dword(value=1000000, endian=BIG_ENDIAN, name="Required Min RX Interval", fuzzable=False)
            s_dword(value=0, endian=BIG_ENDIAN, name="Required Min Echo RX Interval", fuzzable=False)

        self.session.connect(s_get("bfd_discriminators"))
        self.session.fuzz("bfd_discriminators")
