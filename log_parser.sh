#!/bin/bash

input_folder="./bird-fuzzing"
output_file="./output.txt"

> "$output_file"

for file in "$input_folder"/*; do
  if [[ -f "$file" ]]; then
    last_line=$(tail -n 1 "$file")
    
    if [[ "$last_line" =~ Done\ [0-9]+\ runs\ in\ [0-9]+\ second\(s\) ]]; then
      echo -e "\e[32m$file: $last_line\e[0m" >> "$output_file"
    else
      echo -e "\e[31m$file: Error has occurred\e[0m" >> "$output_file"
    fi
  fi
done
