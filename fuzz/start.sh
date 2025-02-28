#!/bin/bash

docker-compose up --build -d

echo "Ждём, пока bird-container-test запустится..."
while ! docker exec bird-container-test ls /usr/sbin/sshd &>/dev/null; do
  sleep 1
done
echo "bird-container-test запущен."

echo "Запускаем SSH в bird-container-test..."
docker exec bird-container-test /usr/sbin/sshd -D &

echo "Ждём, пока SSH поднимется..."
sleep 3

echo "Запускаем Python-приложение в fuzzer-container..."
docker exec fuzzer-container python3 main.py
