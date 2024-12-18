import subprocess
import socket
from boofuzz import Session, Target, TCPSocketConnection
import json
import paramiko

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
                stdin, stdout, stderr = client.exec_command('tail -n1 /var/log/bird.log')  # Выполняем команду в контейнере
                log_entry = stdout.read().decode().strip()  # Получаем строку из вывода
                if log_entry:  # Если строка не пуста, выводим её
                    print(log_entry)
                client.close()  # Закрываем соединение
        except Exception as e:
            print(f"Failed to read logs of container with bird via SSH: {e}")

    def restart_uplink(self, target=None, fuzz_data_logger=None, session=None, sock=None):
        """Function for restarting BGP protocol in container with bird via SSH"""
        try:
            # Подключаемся по SSH
            client = self.get_ssh_client()
            if client:
                stdin, stdout, stderr = client.exec_command(f'birdc restart {self.BGP_PROTO_NAME}')  # Выполняем команду в контейнере
                result = stdout.read().decode().strip()
                if result:
                    print(f"Restart result: {result}")
                client.close()  # Закрываем соединение
        except Exception as e:
            print(f"Failed to restart BGP_PROTO_NAME via SSH: {e}")

    # def print_new_logs(self, target=None, fuzz_data_logger=None, session=None, sock=None):
    #     """Function for printing logs bird"""
    #     try:
    #         # Reading last string from logs file
    #         process = subprocess.Popen(
    #             ['docker', 'exec', '-i', self.BIRD_CON_NAME, 'tail', '-n1', '/var/log/bird.log'],
    #             stdout=subprocess.PIPE,
    #             stderr=subprocess.PIPE
    #         )
    #         output, _ = process.communicate()  # Reading last string
    #         log_entry = output.decode().strip()
    #         if log_entry:  # If string not empty print it
    #             print(log_entry)
    #     except Exception as e:
    #         print(f"Failed to read logs of container with bird: {e}")

    # def restart_uplink(self, target=None, fuzz_data_logger=None, session=None, sock=None):
    #     """Function for restarting BGP protocol in container with bird"""
    #     try:
    #         subprocess.run(['docker', 'exec', self.BIRD_CON_NAME, 'birdc', 'restart', self.BGP_PROTO_NAME], check=True)
    #     except subprocess.CalledProcessError as e:
    #         print(f"Failed to restart BGP_PROTO_NAME: {e}")
