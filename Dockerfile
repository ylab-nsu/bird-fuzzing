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
    bash \        
    && rm -rf /var/lib/apt/lists/*

WORKDIR /bird-fuzzing

COPY . /bird-fuzzing

RUN autoreconf -i
RUN CC=clang ./configure --prefix=$PWD/out --disable-client
RUN make
RUN make fuzz_tests

RUN chmod +x run.sh log_parser.sh   


CMD bash -c "./run.sh && ./log_parser.sh"
