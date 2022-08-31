FROM ubuntu:18.04

MAINTAINER Christof Torres (christof.torres@uni.lu)

SHELL ["/bin/bash", "-c"]
RUN apt-get update -q && \
    apt-get install -y \
    pkg-config pandoc python-setuptools python-pip python-dev python-virtualenv git build-essential software-properties-common python3-pip && \
    apt-get clean -q && rm -rf /var/lib/apt/lists/*

WORKDIR /root

# Install Python 3.8
RUN add-apt-repository ppa:deadsnakes/ppa && apt-get install -y python3.8 python3.8-dev

# Install SCRepair
COPY screpair screpair
RUN cd screpair && python3.8 setup.py install

ENTRYPOINT ["python3.8", "-m", "screpair.CLI.py"]
