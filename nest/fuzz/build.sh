#!/bin/bash

SKIP_STEPS=("$@")

# skip check function
should_skip() {
    local step=$1
    for skip in "${SKIP_STEPS[@]}"; do
        if [[ "$skip" == "$step" ]]; then
            return 0  
        fi
    done
    return 1 
}

should_hide_stdin() {
    for hide_flag in "${SKIP_STEPS[@]}"; do
        if [[ "$hide_flag" == "stdin" ]]; then
            return 0  
        fi
    done
    return 1 
}

if ! should_skip 1; then
    echo "STEP_1: CC=clang ./configure --prefix=$PWD/out --disable-client"
    if should_hide_stdin; then 
        CC=clang ./configure --prefix=$PWD/out --disable-client 1>/dev/null
    else 
        CC=clang ./configure --prefix=$PWD/out --disable-client
    fi
else
    echo "STEP_1: SKIP"
fi

if ! should_skip 2; then
    echo "STEP_2: make"
    if should_hide_stdin; then 
        make 1>/dev/null
    else 
        make
    fi
else
    echo "STEP_2: SKIP"
fi

if ! should_skip 3; then
    echo "STEP_3: make fuzz_tests"
    if should_hide_stdin; then
        make fuzz_tests 1>/dev/null
    else
        make fuzz_tests
    fi
else
    echo "STEP_3: SKIP"
fi
