"""
@author: Xiao Liang Yu
"""
import docker
from typing import Any, Sequence, Iterable, ClassVar, Optional
from pathlib import Path
import asyncio
from logbook import Logger
import concurrent
import json
import os
from itertools import chain
from encodings import utf_8

def mean(tu):
    return sum(tu) / len(tu)



logger = Logger(os.path.basename(__file__))

class GR():

    name: str = 'Oyente'
    docker_image: str
    dockerCl: Any
    parallelized: bool = True
    threadPool: ClassVar[concurrent.futures.ThreadPoolExecutor] = concurrent.futures.ThreadPoolExecutor()

    def __init__(self, docker_image: str):
        super().__init__()
        self.docker_image = docker_image
        self.dockerCl = docker.from_env()
    
    async def rankGas(self, path_source: Iterable[Path], contractName: Optional[str] = None) -> int:
        
        logger.debug('Going to start Oyente container')
        
        arg_parallelized = '' if not self.parallelized else '--parallel'
        # The --web flag is to make it output json format
        cmd = F'"/oyente/oyente/oyente.py -s /tmp/subject.sol -ce --web {arg_parallelized} --output-path-gas --target-contracts {contractName} || exit 0"'

        def runContainer():
            return self.dockerCl.containers.run(
                image=self.docker_image,
                command=cmd,
                entrypoint='/bin/bash -c',
                detach=False,
                auto_remove=True,
                network_disabled=True,
                network_mode='none',
                tty=False,
                stdin_open=False,
                stdout=True,
                stderr=False,
                volumes={next(iter(path_source)): {
                            'bind': '/tmp/subject.sol',
                            'mode': 'ro'
                        }}).decode(utf_8.getregentry().name)

        output = await asyncio.get_event_loop().run_in_executor(self.threadPool, runContainer)

        logger.trace(F'Oyente output:{os.linesep}{output}')
        # analysis result and build the return dict <BugName,Value>.
        
        try:
            rst_ = json.loads(output)
        except:
            logger.error(F'File being processed: {path_source}')
            logger.error(F'cmd being executed: {cmd}')
            logger.error(F'Oyente output:{os.linesep}{output}')
            raise

        rst = rst_[next(iter(rst_.keys()))]
        
        if contractName is not None:
            if contractName not in rst:
                raise RuntimeError(F"Targeted smart contract {contractName} wasn't processed")

            gas_dict = rst[contractName]['path_gas']
            gasRanking = mean(tuple(gas_dict.values()))

        else:
            gasRanking = mean(tuple(chain(*(rst[k]['path_gas'].values() for k in rst))))

        return gasRanking
