import subprocess
import sys
import select
import time
import argparse

def run_program_and_monitor_logs(command, timeout_duration, log_file):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    outputs = [process.stdout, process.stderr]
    last_new_log_time = time.time()  

    # Открываем файл для записи логов, если указан
    log_file_handle = None
    if log_file:
        log_file_handle = open(log_file, 'a')  # Открываем файл в режиме добавления

    try:
        while True:
            readable, _, _ = select.select(outputs, [], [])

            for stream in readable:
                line = stream.readline()
                if line:
                    print(line, end='')  # Печатаем в консоль

                    # Записываем в файл, если он указан
                    if log_file_handle:
                        log_file_handle.write(line)

                    if "NEW" in line:
                        last_new_log_time = time.time()  

                else:
                    outputs.remove(stream)

            if process.poll() is not None:
                break

            if time.time() - last_new_log_time > timeout_duration:
                print(f"\nНе было новых логов 'NEW' в течение {timeout_duration} секунд. Завершение программы.")
                process.terminate()  
                break

    except KeyboardInterrupt:
        print("\nПользователь прервал выполнение программы.")
        process.terminate()  
        process.wait() 

    return_code = process.wait()
    print(f"Процесс завершился с кодом: {return_code}")

    # Закрываем файл, если он был открыт
    if log_file_handle:
        log_file_handle.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Запуск программы с мониторингом логов.")
    parser.add_argument('command', type=str, help="Команда для запуска программы.")
    parser.add_argument('-t', '--timeout', type=int, default=60, help="Время ожидания в секундах (по умолчанию 60).")
    parser.add_argument('-f', '--file', type=str, help="Файл для записи логов.")

    args = parser.parse_args()

    command = args.command.split()
    timeout_duration = args.timeout
    log_file = args.file

    run_program_and_monitor_logs(command, timeout_duration, log_file)

# example 
#  python3 ./nest/fuzz/wrapper.py ./obj/nest/fuzz/rt-fib_fuzz_mostly_negative_matches -t 3 