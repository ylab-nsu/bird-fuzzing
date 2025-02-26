FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    build-essential \          
    bison \                    
    m4 \                       
    flex \                     
    libncurses5-dev \          
    libncursesw5-dev \         
    libreadline-dev \          
    libssh-dev \               
    linuxdoc-tools \           
    texlive \                  
    autoconf \                 
    automake \        
    clang \         
    && rm -rf /var/lib/apt/lists/*

WORKDIR /bird-fuzzing

COPY . /bird-fuzzing

RUN autoreconf -i
RUN CC=clang ./configure --prefix=$PWD/out --disable-client
RUN make
RUN make fuzz_tests

CMD ["sh", "-c", "./obj/nest/fuzz/rt-fib_fuzz_mostly_negative_matches", "-max_len=8192", "-use_counters=1", "-use_memmem=1", "-runs=1000"]

