#!/bin/bash

echo "Очищаем папку output..."
rm -rf output/*

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

MAX_TESTS=1

echo "Запускаем тесты с pytest..."
docker exec -it fuzzer-container pytest tests/ --max-tests=$MAX_TESTS -v | tee output/pytest_output.txt