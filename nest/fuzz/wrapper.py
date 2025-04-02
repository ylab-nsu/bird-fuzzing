import subprocess
import sys
import select
import time
import argparse

def run_program_and_monitor_logs(command, timeout_duration):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


    outputs = [process.stdout, process.stderr]
    last_new_log_time = time.time()  

    try:
        while True:
            readable, _, _ = select.select(outputs, [], [])

            for stream in readable:
                line = stream.readline()
                if line:
                    print(line, end='')  


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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Запуск программы с мониторингом логов.")
    parser.add_argument('command', type=str, help="Команда для запуска программы.")
    parser.add_argument('-t', '--timeout', type=int, default=60, help="Время ожидания в секундах (по умолчанию 60).")

    args = parser.parse_args()

    command = args.command.split()
    timeout_duration = args.timeout

    run_program_and_monitor_logs(command, timeout_duration)
# example 
#  python3 ./nest/fuzz/wrapper.py ./obj/nest/fuzz/rt-fib_fuzz_mostly_negative_matches -t 3 