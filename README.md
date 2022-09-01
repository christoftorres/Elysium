<img src="https://cdn-icons-png.flaticon.com/512/3196/3196633.png" width="64"> Elysium
=======

A tool to automatically patch vulnerable Ethereum smart contracts. This repository also includes the data, tools, and results from our paper. Our paper can be found [here](https://arxiv.org/pdf/2108.10071.pdf).

## Installation Instructions

### 1. Install Docker

##### MacOS

Download and install Docker Desktop for Mac: https://docs.docker.com/desktop/mac/install/

For other operating systems follow the installation instructions on [docker.com](https://docs.docker.com/desktop/).

### 2. Install required tools

``` shell
python3 -m pip install maturin
python3 -m pip install solc-select
```

### 3. Install Python dependencies

``` shell
cd elysium
python3 -m pip install -r requirements.txt
```

## Running Instructions

##### Install Solidity compiler version 0.4.24 using solc-select

```
solc-select install 0.4.24
solc-select use 0.4.24
```
##### Pull Docker images of detectors and evaluated tools

```
docker pull christoftorres/osiris
docker pull christoftorres/oyente
docker pull christoftorres/mythril
```

```
docker pull christoftorres/smartshield
docker pull christoftorres/sguard
```
##### Run Elysium

``` shell
cd elysium

# Example patching multiple integer overflows
python3 elysium.py -s ../evaluation/datasets/SWC/SWC-101/tokensalechallenge/tokensalechallenge.sol --cfg

# Example patching integer underflow
python3 elysium.py -s ../evaluation/datasets/SWC/SWC-101/subtraction/integer_overflow_minimal/integer_overflow_minimal.sol -c IntegerOverflowMinimal --cfg

# Example patching unhandled exceptions
python3 elysium.py -s ../evaluation/datasets/SWC/SWC-104/unchecked_return_value.sol -c ReturnValue --cfg

# Example patching leaking ether
python3 elysium.py -s ../evaluation/datasets/SWC/SWC-105/simple_ether_drain.sol -c SimpleEtherDrain --cfg

# Example patching suicidal contract
python3 elysium.py -s ../evaluation/datasets/SWC/SWC-106/simple_suicide.sol -c SimpleSuicide --cfg

# Example patching reentrancy and integer overflow
python3 elysium.py -s ../evaluation/datasets/SWC/SWC-107/simple_dao.sol -c SimpleDAO --cfg

# Example patching unsafe delegatecall
python3 elysium.py -s ../evaluation/datasets/SWC/SWC-112/proxy.sol -c Proxy --cfg 

# Example patching transaction origin
python3 elysium.py -s ../evaluation/datasets/SWC/SWC-115/mycontract.sol -c MyContract --cfg
```
