import time

from boofuzz import *
from bgp_fuzz_test import BGFuzzTest

BGP_HEADER_SIZE = 16
BGP_VERSION = 0x04
BGP_TYPE = 0x01
MAX_BGP_OPTIONAL_PARAM_LEN = 4096
MAX_ASN_VALUE = 65535
MAX_HOLD_TIME = 65535
MAX_BGP_ID = 0xFFFFFFFF
DEFAULT_HOLD_TIME = 90


class BgpUpdateFuzzer(BGFuzzTest):
    def __init__(self, config_file, test_results):
        super().__init__(config_file)
        self.cur = 0
        self.cur2 = 0
        self.test_results = test_results

    def fuzz(self, name):
        # Добавляем замер времени и статуса
        start_time = time.time()  # Запоминаем время начала
        try:
            self.session.fuzz()
            status = "Success"
        except Exception as e:
            status = f"Failed: {e}"
        finally:
            elapsed_time = time.time() - start_time  # Вычисляем затраченное время
            self.test_results.add_result(name, status,  self.max_tests, str(elapsed_time))
            print(f"Test {name} {self.max_tests} {status} {elapsed_time:.2f} seconds")

    @staticmethod
    def initialize_bgp_header(block_name):
        with s_block(block_name):
            s_bytes(value=b'\xFF' * BGP_HEADER_SIZE, padding=b'\xFF', size=BGP_HEADER_SIZE, name='Marker',
                    fuzzable=False)
            s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
            s_byte(value=BGP_TYPE, endian=BIG_ENDIAN, name='Type', fuzzable=False)

    def create_bgp_open(self):
        s_initialize('bgp_open' + str(self.cur))
        self.cur += 1
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
        return s_get('bgp_open' + str(self.cur - 1))


    def create_bgp_keepalive(self):
        s_initialize('BGP_KEEPALIVE' + str(self.cur2))
        self.cur2 += 1
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_static(name='length', value=b'\x00\x13')
            s_static(name='type', value=b'\x04')
        return s_get('BGP_KEEPALIVE' + str(self.cur2 - 1))

    def update_test_with_withdrawn_routes(self):
        """
        Создает тест, в котором заполнено поле withdrawn routes.
        Например, можно задать несколько префиксов для отзыва.
        """
        s_initialize('BGP_UPDATE_with_withdrawn')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_size(name='withdrawn_routes_length', length=2, block_name='withdrawn_routes', endian=BIG_ENDIAN,
                       fuzzable=False)
                with s_block('withdrawn_routes'):
                    # Префикс 1
                    s_static(name='prefix1_len', value=b'\x20')  # длина 32 бита
                    s_static(name='prefix1_addr', value=b'\xc0\xa8\x01\x01')  # 192.168.1.1
                    # Префикс 2
                    s_static(name='prefix2_len', value=b'\x18')  # длина 24 бита
                    s_static(name='prefix2_addr', value=b'\x0a\x00\x00')  # 10.0.0.0
                # Поле total path attribute length
                s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZLOAD'):
                    # Пусть здесь остается пространство для стандартных атрибутов пути
                    # Используем s_random для генерации набора данных, чтобы проверить, как система обрабатывает данные
                    s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)
        # Устанавливаем последовательность сообщений
        self.session.connect(self.create_bgp_open())
        self.session.connect(s_get('bgp_open0'), self.create_bgp_keepalive())
        self.session.connect(s_get('BGP_KEEPALIVE0'), s_get('BGP_UPDATE_with_withdrawn'))
        self.fuzz('BGP_UPDATE_with_withdrawn')

    def update_test_with_incorrect_path_attrs(self):
        """
        Тест, где в поле path attributes намеренно вставляются некорректные данные
        (например, слишком большая длина, или не корректная структура атрибутов).
        """
        s_initialize('BGP_UPDATE_with_incorrect_attrs')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            # Вычисляем общую длину с учетом обновленного блока
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_word(name='withdrawn_len', value=b'\x00\x00', endian=BIG_ENDIAN, fuzzable=False)
                # Определяем поле total path attribute length, которое может быть невалидным (например, завышенным)
                s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZLOAD'):
                    # Здесь зададим некорректную структуру данных:
                    # Например, фиксированное значение слишком большого размера
                    s_static(name='incorrect_attrs', value=b'\xff' * 1500)
        # Последовательность отправки сообщений
        self.session.connect(self.create_bgp_open())
        self.session.connect(s_get('bgp_open1'), self.create_bgp_keepalive())
        self.session.connect(s_get('BGP_KEEPALIVE1'), s_get('BGP_UPDATE_with_incorrect_attrs'))
        self.fuzz('BGP_UPDATE_with_incorrect_attrs')

    def update_test_with_valid_withdrawn_routes(self):
        """
        Тест с корректными маршрутами для отзыва.
        """
        s_initialize('BGP_UPDATE_valid_withdrawn')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_size(name='withdrawn_routes_length', length=2, block_name='withdrawn_routes', endian=BIG_ENDIAN,
                       fuzzable=False)
                with s_block('withdrawn_routes'):
                    # Префикс 1: 192.168.1.0/24
                    s_byte(name='prefix1_len', value=24)
                    s_bytes(name='prefix1_addr', value=b'\xc0\xa8\x01', size=3)
                    # Префикс 2: 10.0.0.0/8
                    s_byte(name='prefix2_len', value=8)
                    s_bytes(name='prefix2_addr', value=b'\x0a', size=1)
                # Поле total path attribute length
                s_size(name='total_path_attr_len', length=2, block_name='path_attributes', endian=BIG_ENDIAN,
                       fuzzable=False)
                with s_block('path_attributes'):
                    # Пример корректного атрибута ORIGIN (значение 0 — IGP)
                    s_byte(name='attr_flags', value=0x40)  # Optional, Transitive
                    s_byte(name='attr_type', value=0x01)  # ORIGIN
                    s_byte(name='attr_length', value=1)
                    s_byte(name='attr_value', value=0x00)  # IGP
                # NLRI (новые префиксы для анонса)
                s_byte(name='nlri_prefix_len', value=24)
                s_bytes(name='nlri_prefix_addr', value=b'\xc0\xa8\x02', size=3)  # 192.168.2.0/24
        # Устанавливаем последовательность сообщений
        self.session.connect(self.create_bgp_open())
        self.session.connect(s_get('bgp_open2'), self.create_bgp_keepalive())
        self.session.connect(s_get('BGP_KEEPALIVE2'), s_get('BGP_UPDATE_valid_withdrawn'))
        self.fuzz('BGP_UPDATE_valid_withdrawn')

    def update_test_fuzz_withdrawn_routes_length(self):
        """
        Тест для фаззинга поля Withdrawn Routes Length.
        """
        s_initialize('BGP_UPDATE_fuzz_withdrawn_len')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_size(name='withdrawn_routes_length', length=2, block_name='withdrawn_routes', endian=BIG_ENDIAN,
                       fuzzable=True)  # Фаззим это поле
                with s_block('withdrawn_routes'):
                    s_static(name='prefix1_len', value=b'\x20')  # длина 32 бита
                    s_static(name='prefix1_addr', value=b'\xc0\xa8\x01\x01')  # 192.168.1.1
                s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZLOAD'):
                    s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)
        # Устанавливаем последовательность сообщений
        self.session.connect(self.create_bgp_open())
        self.session.connect(s_get('bgp_open1'), self.create_bgp_keepalive())
        self.session.connect(s_get('BGP_KEEPALIVE1'), s_get('BGP_UPDATE_fuzz_withdrawn_len'))
        self.fuzz('BGP_UPDATE_fuzz_withdrawn_len')

    def update_test_fuzz_withdrawn_routes(self):
        """
        Тест для фаззинга поля Withdrawn Routes (префиксы для отзыва).
        """
        s_initialize('BGP_UPDATE_fuzz_withdrawn_routes')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_static(name='withdrawn_routes_length', value=b'\x00\x08')  # Статическое поле (2 префикса по 4 байта)
                with s_block('withdrawn_routes'):
                    s_byte(name='prefix1_len', value=32, fuzzable=True)  # Фаззим длину префикса
                    s_bytes(name='prefix1_addr', value=b'\xc0\xa8\x01\x01', size=4,
                            fuzzable=True)  # Фаззим адрес префикса
                s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZLOAD'):
                    s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)
        # Устанавливаем последовательность сообщений
        self.session.connect(self.create_bgp_open())
        self.session.connect(s_get('bgp_open4'), self.create_bgp_keepalive())
        self.session.connect(s_get('BGP_KEEPALIVE4'), s_get('BGP_UPDATE_fuzz_withdrawn_routes'))
        self.fuzz('BGP_UPDATE_fuzz_withdrawn_routes')

    def update_test_fuzz_path_attributes_length(self):
        """
        Тест для фаззинга поля Path Attributes Length.
        """
        s_initialize('BGP_UPDATE_fuzz_path_attr_len')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_static(name='withdrawn_routes_length', value=b'\x00\x00')  # Статическое поле
                s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN,
                       fuzzable=True)  # Фаззим это поле
                with s_block('FUZZLOAD'):
                    s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)
        # Устанавливаем последовательность сообщений
        self.session.connect(self.create_bgp_open())
        self.session.connect(s_get('bgp_open2'), self.create_bgp_keepalive())
        self.session.connect(s_get('BGP_KEEPALIVE2'), s_get('BGP_UPDATE_fuzz_path_attr_len'))
        self.fuzz('BGP_UPDATE_fuzz_path_attr_len')

    def update_test_fuzz_path_attributes(self):
        """
        Тест для фаззинга полей Path Attributes.
        """
        s_initialize('BGP_UPDATE_fuzz_path_attrs')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_static(name='withdrawn_routes_length', value=b'\x00\x00')  # Статическое поле
                s_size(name='total_path_attr_len', length=2, block_name='path_attributes', endian=BIG_ENDIAN,
                       fuzzable=False)
                with s_block('path_attributes'):
                    s_byte(name='attr_flags', value=0x40, fuzzable=True)  # Фаззим флаги
                    s_byte(name='attr_type', value=0x01, fuzzable=True)  # Фаззим тип
                    s_byte(name='attr_length', value=1, fuzzable=True)  # Фаззим длину
                    s_byte(name='attr_value', value=0x00, fuzzable=True)  # Фаззим значение
                s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZLOAD'):
                    s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)
        # Устанавливаем последовательность сообщений
        self.session.connect(self.create_bgp_open())
        self.session.connect(s_get('bgp_open6'), self.create_bgp_keepalive())
        self.session.connect(s_get('BGP_KEEPALIVE6'), s_get('BGP_UPDATE_fuzz_path_attrs'))
        self.fuzz('BGP_UPDATE_fuzz_path_attrs')

    def update_test_fuzz_nlri(self):
        """
        Тест для фаззинга поля NLRI.
        """
        s_initialize('BGP_UPDATE_fuzz_nlri')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN,
                   fuzzable=False)
            s_static(name='type', value=b'\x02')
            with s_block('UPDATE'):
                s_static(name='withdrawn_routes_length', value=b'\x00\x00')  # Статическое поле
                s_size(name='total_path_attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
                with s_block('FUZZLOAD'):
                    s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)
                s_byte(name='nlri_prefix_len', value=24, fuzzable=True)  # Фаззим длину префикса
                s_bytes(name='nlri_prefix_addr', value=b'\xc0\xa8\x02', size=3, fuzzable=True)  # Фаззим адрес префикса
        # Устанавливаем последовательность сообщений
        self.session.connect(self.create_bgp_open())
        self.session.connect(s_get('bgp_open3'), self.create_bgp_keepalive())
        self.session.connect(s_get('BGP_KEEPALIVE3'), s_get('BGP_UPDATE_fuzz_nlri'))
        self.fuzz('BGP_UPDATE_fuzz_nlri')