FROM ubuntu:18.04

MAINTAINER Christof Torres (christof.torres@uni.lu)

SHELL ["/bin/bash", "-c"]
RUN apt-get update -q && \
    apt-get install -y \
    pkg-config pandoc python-setuptools python-pip python-dev python-virtualenv git build-essential software-properties-common python3-pip && \
    apt-get clean -q && rm -rf /var/lib/apt/lists/*

WORKDIR /root
COPY smartshield smartshield

# Install SMARTSHIELD
RUN cd smartshield && python3 -m pip install -r requirements.txt

ENTRYPOINT ["python3", "./smartshield/evm_rewriter.py"]
