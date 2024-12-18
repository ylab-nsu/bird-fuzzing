FROM ungleich/bird:3.20.1-2.15.1

COPY bird.conf /etc/bird.conf

RUN apk update && apk add --no-cache openssh

# configure SSH
RUN mkdir /var/run/sshd \
    && echo 'root:password' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config \
    && ssh-keygen -A

EXPOSE 22