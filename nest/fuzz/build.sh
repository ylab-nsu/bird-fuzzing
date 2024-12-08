CC=clang ./configure --prefix=$PWD/out --disable-client
make
make fuzz_tests