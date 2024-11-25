import time
from boofuzz import *
from scapy.all import *

def restart_uplink(target=None, fuzz_data_logger=None, session=None, sock=None):
    try:
        subprocess.run(['docker', 'exec', 'bird1a', 'birdc', 'restart', 'uplink'], check=True)
        print("Uplink перезапущен.")
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при перезапуске uplink: {e}")

log_buffer = []

def print_new_logs(target=None, fuzz_data_logger=None, session=None, sock=None):
    global log_buffer
    try:
        # Чтение последней строки из файла логов
        process = subprocess.Popen(
            ['docker', 'exec', '-i', 'bird1a', 'tail', '-n1', '/var/log/bird.log'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output, _ = process.communicate()  # Читаем последнюю строку
        log_entry = output.decode().strip()
        if log_entry:  # Если строка не пустая, выводим её
            print("Новая запись в логах:")
            print(log_entry)
    except Exception as e:
        print(f"Ошибка при чтении логов контейнера Bird: {e}")




def ip_str_to_bytes(ip):
    """Преобразование IP-адреса в байты."""
    return int.from_bytes(socket.inet_aton(ip), 'big')

def fuzz_open_and_keepalive(dst_ip, dst_port):
    """Фаззинг Open Message с последующим Keepalive."""
    PARAM_ASN_ID = 65002
    PARAM_BGP_ID = "172.18.0.1"
    PARAM_HOLD_TIME = 180

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
            s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
            s_dword(value=ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
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
    # Соединение Open -> Keepalive
    session.connect(s_get("bgp_open"))
    session.connect(s_get("bgp_open"), s_get("bgp_keepalive"))
    session.fuzz()


# Выполнение фаззинг-теста
fuzz_open_and_keepalive('172.18.0.2', 179)
