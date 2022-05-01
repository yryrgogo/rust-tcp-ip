FROM ubuntu:20.04

RUN apt update \
	&& apt install sudo \
	&& sudo apt-get update \
	&& sudo apt-get -y install bash coreutils grep \
	iproute2 iputils-ping traceroute tcpdump bind9-dnsutils \
	dnsmasq-base netcat-openbsd python3 curl wget iptables \
	procps isc-dhcp-client ethtool
