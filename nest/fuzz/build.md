Возможно потребуются права sudo при запуске скрипта или изменить права доступа к файлу - `sudo chmod 777 {/path/to/build.sh}`  
Скомпилированные файлы будут лежать в `obj` папке  
`./obj/nest/fuzz/rt-fib_test_fuzz` запуск некоторого теста, есть много параметров описаны здесь - `https://llvm.org/docs/LibFuzzer.html`  
Есть несколько параметров:  
- числами указывается какие шаги нужно пропустить build.sh 1 2 выполнит только последний шаг  
- stdout, stderr - позволяет перенаправить каждый из этих потоков /dev/null сокращает вывод до такого вида:  
```
2024-12-09 21:04:45 STEP_1: CC=clang ./configure --prefix=/home/ruslan/repos/bird-fuzzing/out --disable-client
2024-12-09 21:04:47 STEP_2: make
2024-12-09 21:05:05 STEP_3: make fuzz_tests
```


