FROM phusion/baseimage:0.9.15

MAINTAINER Sandro Mello

# Set correct environment variables.
ENV HOME /root

# Regenerate SSH host keys. baseimage-docker does not contain any, so you
# have to do that yourself. You may also comment out this instruction; the
# init system will auto-generate one during boot.
RUN /etc/my_init.d/00_regen_ssh_host_keys.sh

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

RUN apt-get update
RUN apt-get upgrade -y

RUN add-apt-repository ppa:sandro-mello/themis-core -y
RUN add-apt-repository ppa:sandro-mello/themis -y
RUN add-apt-repository ppa:chris-lea/python-redis -y 
RUN add-apt-repository ppa:chris-lea/python-hiredis -y 

RUN apt-get update
RUN apt-get install themis-core themis --force-yes -y

EXPOSE 8440

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
