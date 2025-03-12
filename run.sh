#!/bin/bash

input_folder="./obj/nest/fuzz"

output_folder="./bird-fuzzing"

if [ ! -d "$output_folder" ]; then
  mkdir -p "$output_folder"
  echo "Создана папка для выводов: $output_folder"
fi

for file in "$input_folder"/*; do
  if [[ -x "$file" && -f "$file" ]]; then
    filename=$(basename "$file")
    output_file="${filename%.*}.txt"
    
    if [-z "$RUNS_NUM"]; then
      "$file" -runs=1000 2> "$output_folder/$output_file"
    else
      "file" -runs=$RUNS_NUM 2> "$output_folder/$output_file"
    fi
    echo "Запущен: $file, вывод сохранен в $output_folder/$output_file"
  fi
done
