FROM ubuntu:18.04

MAINTAINER Christof Torres (christof.torres@uni.lu)

SHELL ["/bin/bash", "-c"]
RUN apt-get update -q && \
    apt-get install -y \
    pkg-config git build-essential software-properties-common curl wget && \
    apt-get clean -q && rm -rf /var/lib/apt/lists/*

# Install Node.js
RUN curl -sL https://deb.nodesource.com/setup_10.x -o nodesource_setup.sh && bash nodesource_setup.sh && apt-get install -y nodejs
RUN nodejs -v
RUN npm -v

WORKDIR /root
COPY src src
COPY package-lock.json package-lock.json
COPY package.json package.json

# Install node dependencies
RUN npm install

# Install solc
RUN wget https://github.com/ethereum/solidity/releases/download/v0.4.26/solc-static-linux && mv solc-static-linux /usr/local/bin/solc && chmod +x /usr/local/bin/solc
