# Pull from source
FROM centos:7
MAINTAINER team@traversys.io

# Setup the environment
RUN yum clean all
RUN yum -y --enablerepo=extras install epel-release && \
yum -y install centos-release-scl && \
yum -y install nmap && \
yum -y install python27 && \
yum -y install net-tools && \
yum -y install openssh-server openssh-clients && \
yum -y install python-pip
RUN easy_install pyinstaller==3.6

CMD ["/bin/bash"]

#
# Build Docker image:
#
# docker build --tag getcert .   # creates image getcert
#
# Run Docker Container
#
# docker run -it -v <your git dir>:/usr/dev getcert:latest
#
