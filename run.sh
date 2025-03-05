#!/bin/bash

# Папка, где находятся исполняемые файлы
input_folder="./obj/nest/fuzz"

# Папка, куда будут сохраняться выводы в .txt
output_folder="./bird-fuzzing"

# Проверяем, существует ли папка для вывода. Если нет, создаем её.
if [ ! -d "$output_folder" ]; then
  mkdir -p "$output_folder"
  echo "Создана папка для выводов: $output_folder"
fi

# Проходим по всем файлам в директории input_folder
for file in "$input_folder"/*; do
  # Проверяем, является ли это исполняемым файлом
  if [[ -x "$file" && -f "$file" ]]; then
    # Извлекаем имя файла без пути
    filename=$(basename "$file")
    # Убираем расширение, чтобы добавить .txt
    output_file="${filename%.*}.txt"
    
    # Запускаем исполняемый файл и перенаправляем вывод в файл в целевой директории
    "$file" -runs=1000 2> "$output_folder/$output_file"
    
    echo "Запущен: $file, вывод сохранен в $output_folder/$output_file"
  fi
done
