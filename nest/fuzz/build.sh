#!/bin/bash

SKIP_STEPS=("$@")
# launch commands from root of project
SCRIPT_DIR="$(dirname "$(realpath "$0")")"
cd $SCRIPT_DIR 
cd ../..

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

should_hide_stdout() {
    for hide_flag in "${SKIP_STEPS[@]}"; do
        if [[ "$hide_flag" == "stdout" ]]; then
            return 0  
        fi
    done
    return 1 
}

should_hide_stderr() {
    for hide_flag in "${SKIP_STEPS[@]}"; do
        if [[ "$hide_flag" == "stderr" ]]; then
            return 0  
        fi
    done
    return 1 
}

redirect_output() {
    local command=$1
    local stdout_redirect=""
    local stderr_redirect=""

    if should_hide_stdout; then
        stdout_redirect="1>/dev/null"
    fi

    if should_hide_stderr; then
        stderr_redirect="2>/dev/null"
    fi

    eval "$command $stdout_redirect $stderr_redirect"
}

print_time() {
    echo "$(date '+%Y-%m-%d %H:%M:%S')"
}






if ! should_skip 1; then
    echo "$(print_time) STEP_1: CC=clang ./configure --prefix=$PWD/out --disable-client"
    redirect_output "CC=clang ./configure --prefix=$PWD/out --disable-client"
else
    echo "$(print_time) STEP_1: SKIP"
fi

if ! should_skip 2; then
    echo "$(print_time) STEP_2: make"
    redirect_output "make"
else
    echo "$(print_time) STEP_2: SKIP"
fi

if ! should_skip 3; then
    echo "$(print_time) STEP_3: make fuzz_tests"
    redirect_output "make fuzz_tests"
else
    echo "$(print_time) STEP_3: SKIP"
fi

