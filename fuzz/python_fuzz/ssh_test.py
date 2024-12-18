import paramiko

def execute_command(host, port, username, password, command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=port, username=username, password=password)

    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()

    ssh.close()
    return output, error

if __name__ == "__main__":
    # Настройки подключения
    host = "192.168.100.10"  # IP bird-контейнера
    port = 22
    username = "root"
    password = "password"
    command = "birdc show protocols"  # Пример команды

    # Выполняем команду
    output, error = execute_command(host, port, username, password, command)
    print("Output:", output)
    print("Error:", error)
