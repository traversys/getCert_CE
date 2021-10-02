# Pull from source
FROM centos:7
MAINTAINER team@traversys.io

# Setup the environment
RUN yum clean all
RUN yum -y --enablerepo=extras install epel-release && \
yum -y install centos-release-scl && \
yum -y install nmap && \
yum -y install python3 && \
yum -y install net-tools && \
yum -y install openssh-server openssh-clients && \
yum -y install python3-pip && \
yum -y install zlib-devel && \
yum -y install openssl && \
yum -y groupinstall "Development Tools"
# Pip Packages
RUN pip3 install pyinstaller==3.6
RUN pip3 install wheel
RUN pip3 install tideway
# Setup SSHD
RUN mkdir /var/run/sshd
RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN useradd getcert
RUN SSHPASS="$(openssl rand -base64 20)" && echo "getcert:$SSHPASS" | chpasswd && echo "getcert user password: $SSHPASS"

ENTRYPOINT ["/usr/sbin/sshd", "-D"]

#
# Build Docker image:
#
# docker build --tag getcert . # creates image getcert
#
# Run Docker Container
#
# docker run -it -p 2222:22 -v <your git dir>:/usr/dev getcert:latest
#
