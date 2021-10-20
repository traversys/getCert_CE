# Pull from source
FROM centos:7
LABEL org.opencontainers.image.authors="team@traversys.io"

# Setup the environment
RUN yum clean all
RUN yum -y --enablerepo=extras install epel-release && \
yum -y install centos-release-scl && \
yum install -y coreutils && \
yum -y install nmap && \
yum -y install python3 && \
yum -y install net-tools && \
yum -y install openssh-server openssh-clients && \
yum -y install python3-pip && \
yum -y install makeself && \
yum -y install zlib-devel && \
yum -y install openssl && \
yum -y install cronie && \
yum -y install supervisor && \
yum -y groupinstall "Development Tools"
# Pip Packages
RUN pip3 install pyinstaller==3.6
RUN pip3 install wheel
RUN pip3 install tideway
RUN pip3 install python-dotenv
RUN pip3 install python-crontab
# Setup sshd
RUN mkdir /var/run/sshd
RUN /usr/bin/ssh-keygen -A
RUN useradd getcert
RUN SSHPASS="$(openssl rand -base64 20)" && echo "getcert:$SSHPASS" | chpasswd && echo "getcert user password: $SSHPASS"
# Start running services
COPY dockerbuild/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
EXPOSE 22
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

