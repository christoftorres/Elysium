#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .db import EmulatorMemoryDB, EmulatorAccountDB

from eth import Chain, constants
from eth.chains.mainnet import (
    MAINNET_GENESIS_HEADER,
    HOMESTEAD_MAINNET_BLOCK,
    TANGERINE_WHISTLE_MAINNET_BLOCK,
    SPURIOUS_DRAGON_MAINNET_BLOCK,
    BYZANTIUM_MAINNET_BLOCK,
    PETERSBURG_MAINNET_BLOCK,
    ISTANBUL_MAINNET_BLOCK,
    MUIR_GLACIER_MAINNET_BLOCK,
)
from eth.chains.mainnet import MainnetHomesteadVM
from eth.vm.forks import (
    FrontierVM,
    TangerineWhistleVM,
    SpuriousDragonVM,
    ByzantiumVM,
    PetersburgVM,
    IstanbulVM,
    MuirGlacierVM,
)
from eth.vm.forks.frontier import FrontierState
from eth.vm.forks.homestead import HomesteadState
from eth.vm.forks.tangerine_whistle import TangerineWhistleState
from eth.vm.forks.spurious_dragon import SpuriousDragonState
from eth.vm.forks.byzantium import ByzantiumState
from eth.vm.forks.petersburg import PetersburgState
from eth.vm.forks.istanbul import IstanbulState
from eth.vm.forks.muir_glacier import MuirGlacierState

from eth.vm.forks.frontier.computation import FrontierComputation
from eth.vm.forks.homestead.computation import HomesteadComputation
from eth.vm.forks.tangerine_whistle.computation import TangerineWhistleComputation
from eth.vm.forks.spurious_dragon.computation import SpuriousDragonComputation
from eth.vm.forks.byzantium.computation import ByzantiumComputation
from eth.vm.forks.petersburg.computation import PetersburgComputation
from eth.vm.forks.istanbul.computation import IstanbulComputation
from eth.vm.forks.muir_glacier.computation import MuirGlacierComputation

from eth.constants import CREATE_CONTRACT_ADDRESS
from eth.db.atomic import AtomicDB
from eth.rlp.accounts import Account
from eth.rlp.headers import BlockHeader
from eth.validation import validate_uint256
from eth.vm.spoof import SpoofTransaction
from eth_utils import to_canonical_address, decode_hex, encode_hex

from web3 import Web3

global TRACING_ENABLED
TRACING_ENABLED = False

global EXECUTION_TRACE
EXECUTION_TRACE = list()

global GLOBAL_STEP
GLOBAL_STEP = 0

global DEBUG
DEBUG = False

global W3
W3 = None

class EVM:
    def __init__(self, debug=False) -> None:
        global DEBUG

        DEBUG = debug
        chain = Chain.configure(
            __name__='EmulatorChain',
            vm_configuration=(
                (constants.GENESIS_BLOCK_NUMBER, MyFrontierVM),
                (HOMESTEAD_MAINNET_BLOCK, MyHomesteadVM),
                (TANGERINE_WHISTLE_MAINNET_BLOCK, MyTangerineWhistleVM),
                (SPURIOUS_DRAGON_MAINNET_BLOCK, MySpuriousDragonVM),
                (BYZANTIUM_MAINNET_BLOCK, MyByzantiumVM),
                (PETERSBURG_MAINNET_BLOCK, MyPetersburgVM),
                (ISTANBUL_MAINNET_BLOCK, MyIstanbulVM),
                (MUIR_GLACIER_MAINNET_BLOCK, MyMuirGlacierVM),
            ),
        )
        self._memory_db = EmulatorMemoryDB()
        self._chain = chain.from_genesis_header(AtomicDB(self._memory_db), MAINNET_GENESIS_HEADER)
        self._vm = None
        self._block = None

    @property
    def storage(self):
        return self._vm.state._account_db

    def set_vm(self, provider, block):
        self._block = block
        block_header = BlockHeader(difficulty=block.difficulty,
                                   block_number=block.number,
                                   gas_limit=block.gasLimit,
                                   timestamp=block.timestamp,
                                   coinbase=decode_hex(block.miner),
                                   parent_hash=block.parentHash,
                                   uncles_hash=block.uncles,
                                   state_root=block.stateRoot,
                                   transaction_root=block.transactionsRoot,
                                   receipt_root=block.receiptsRoot,
                                   bloom=0,  # default value
                                   gas_used=block.gasUsed,
                                   extra_data=block.extraData,
                                   mix_hash=block.mixHash,
                                   nonce=block.nonce)
        self._vm = self._chain.get_vm(block_header)
        self.storage.set_web3_provider(provider)
        self.storage.set_fork_block_numer(block.number-1)
        global W3
        W3 = Web3(provider)

    def execute(self, tx):
        return self._vm.state.apply_transaction(tx)

    def reset(self):
        self.storage._raw_store_db.wrapped_db.reset()

    def has_account(self, address):
        address = to_canonical_address(address)
        return self._vm.state._account_db._has_account(address)

    def prepare_state(self, transaction, consider_all_transactions=False):
        global DEBUG

        for i in range(0, transaction["transactionIndex"]):
            if consider_all_transactions or transaction["from"] == self._block.transactions[i]["from"] or transaction["to"] == self._block.transactions[i]["to"]:
                if DEBUG:
                    print(i, self._block.transactions[i].hash.hex())
                if self._block.transactions[i].to:
                    _to = to_canonical_address(self._block.transactions[i].to)
                else:
                    _to = b'\0' * 20
                tx = self._vm.create_unsigned_transaction(
                    nonce=self._block.transactions[i].nonce,
                    gas_price=self._block.transactions[i].gasPrice,
                    gas=self._block.transactions[i].gas,
                    to=_to,
                    value=self._block.transactions[i].value,
                    data=decode_hex(self._block.transactions[i].input)
                )
                self.execute(SpoofTransaction(tx, from_=to_canonical_address(self._block.transactions[i]["from"])))

    def deploy_transaction(self, transaction, code=None, gas_limit=None):
        global TRACING_ENABLED
        global EXECUTION_TRACE
        global GLOBAL_STEP

        if code:
            for address in code:
                self.storage.set_code(to_canonical_address(address), code[address])

        TRACING_ENABLED = True
        EXECUTION_TRACE = list()
        GLOBAL_STEP = 0
        if transaction["to"]:
            _to = to_canonical_address(transaction["to"])
        else:
            _to = CREATE_CONTRACT_ADDRESS
        if gas_limit:
            _gas = gas_limit
        else:
            _gas = transaction["gas"]
        tx = self._vm.create_unsigned_transaction(
            nonce=self._vm.state.get_nonce(to_canonical_address(transaction["from"])),
            gas_price=transaction["gasPrice"],
            gas=_gas,
            to=_to,
            value=transaction["value"],
            data=decode_hex(transaction["input"])
        )
        tx = SpoofTransaction(tx, from_=to_canonical_address(transaction["from"]))
        execution_result = self.execute(tx)
        TRACING_ENABLED = False

        return execution_result, EXECUTION_TRACE, self.storage.get_balance(to_canonical_address(transaction["from"]))

    def get_balance(self, address):
        return self.storage.get_balance(address)

    def get_adversary_balance(self):
        return self.storage.get_balance(self._adversary)

    def get_code(self, address):
        return self.storage.get_code(address)

    def set_code(self, address, code):
        return self.storage.set_code(address, code)

    def create_snapshot(self):
        self.snapshot = self.storage.record()

    def restore_from_snapshot(self):
        self.storage.discard(self.snapshot)

    def get_accounts(self):
        return [encode_hex(x) for x in
                self.storage._cache_store_db.wrapped_db["account"].keys()]

from eth.abc import (
    MessageAPI,
    ComputationAPI,
    StateAPI,
    TransactionContextAPI,
)

@classmethod
def my_apply_computation(cls, state: StateAPI, message: MessageAPI, transaction_context: TransactionContextAPI) -> ComputationAPI:
    global TRACING_ENABLED
    global EXECUTION_TRACE
    global GLOBAL_STEP
    global DEBUG
    global W3

    with cls(state, message, transaction_context) as computation:
        # Early exit on pre-compiles
        from eth.vm.computation import NO_RESULT
        precompile = computation.precompiles.get(message.code_address, NO_RESULT)
        if precompile is not NO_RESULT:
            precompile(computation)
            return computation

        opcode_lookup = computation.opcodes
        local_step = 0
        for opcode in computation.code:
            GLOBAL_STEP += 1
            local_step += 1
            try:
                opcode_fn = opcode_lookup[opcode]
            except KeyError:
                from eth.vm.logic.invalid import InvalidOpcode
                opcode_fn = InvalidOpcode(opcode)

            pc = max(0, computation.code.program_counter - 1)
            op = opcode_fn.mnemonic

            if DEBUG or TRACING_ENABLED:
                stack_values = list()
                memory_values = ""
                if op == "SHA3":
                    offset, size = None, None
                    if isinstance(computation._stack.values[-1][1], int):
                        offset = computation._stack.values[-1][1]
                    else:
                        offset = int(computation._stack.values[-1][1].hex(), 16)
                    if isinstance(computation._stack.values[-2][1], int):
                        size = computation._stack.values[-2][1]
                    else:
                        size = int(computation._stack.values[-2][1].hex(), 16)
                    if offset != None and size != None:
                        memory_values = computation._memory._bytes[offset:size].hex()
                for val in computation._stack.values:
                    if isinstance(val[1], int):
                        stack_values.append(hex(val[1]))
                    elif isinstance(val[1], bytes):
                        if val[1].hex().startswith("0x"):
                            stack_values.append(hex(int(val[1].hex(), 16)))
                        else:
                            if val[1].hex():
                                stack_values.append(hex(int("0x"+val[1].hex(), 16)))
                            else:
                                stack_values.append("")

            if DEBUG:
                print(str(GLOBAL_STEP)+"  \t "+str(local_step)+"  \t PC: "+str(pc)+"  \t OPCODE: "+hex(opcode)+" \t ("+op+") \t STACK: "+stack_values+" \t ("+op+") \t MEMORY: "+memory_values)

            if TRACING_ENABLED:
                EXECUTION_TRACE.append({"pc": pc, "opcode": op, "stack": stack_values, "memory": memory_values, "storage_address": computation.msg.storage_address.hex()})

            from eth.exceptions import Halt
            try:
                if opcode == 0x40: # BLOCKHASH
                    computation.stack_push_bytes(W3.eth.getBlock(computation.stack_pop1_int()).hash)
                else:
                    opcode_fn(computation=computation)

                if TRACING_ENABLED:
                    if op.startswith("PUSH"):
                        val = computation._stack.values[-1][1]
                        if isinstance(val, int):
                            EXECUTION_TRACE[-1]["opcode"] = op + hex(val)
                        elif isinstance(val, bytes):
                            if val.hex().startswith("0x"):
                                EXECUTION_TRACE[-1]["opcode"] = op + " " + val.hex()
                            else:
                                EXECUTION_TRACE[-1]["opcode"] = op + " 0x" + val.hex()
            except Halt:
                break

    return computation

# VMs
# FRONTIER
MyFrontierComputation = FrontierComputation.configure(
    __name__='MyFrontierComputation',
    apply_computation=my_apply_computation,
)
MyFrontierState = FrontierState.configure(
    __name__='MyFrontierState',
    computation_class=MyFrontierComputation,
    account_db_class=EmulatorAccountDB,
)
MyFrontierVM = FrontierVM.configure(
    __name__='MyFrontierVM',
    _state_class=MyFrontierState,
)

# HOMESTEAD
MyHomesteadComputation = HomesteadComputation.configure(
    __name__='MyHomesteadComputation',
    apply_computation=my_apply_computation,
)
MyHomesteadState = HomesteadState.configure(
    __name__='MyHomesteadState',
    computation_class=MyHomesteadComputation,
    account_db_class=EmulatorAccountDB,
)
MyHomesteadVM = MainnetHomesteadVM.configure(
    __name__='MyHomesteadVM',
    _state_class=MyHomesteadState,
)

# TANGERINE WHISTLE
MyTangerineWhistleComputation = TangerineWhistleComputation.configure(
    __name__='MyTangerineWhistleComputation',
    apply_computation=my_apply_computation,
)
MyTangerineWhistleState = TangerineWhistleState.configure(
    __name__='MyTangerineWhistleState',
    computation_class=MyTangerineWhistleComputation,
    account_db_class=EmulatorAccountDB,
)
MyTangerineWhistleVM = TangerineWhistleVM.configure(
    __name__='MyTangerineWhistleVM',
    _state_class=MyTangerineWhistleState,
)

# SPURIOUS DRAGON
MySpuriousDragonComputation = SpuriousDragonComputation.configure(
    __name__='MySpuriousDragonComputation',
    apply_computation=my_apply_computation,
)
MySpuriousDragonState = SpuriousDragonState.configure(
    __name__='MySpuriousDragonState',
    computation_class=MySpuriousDragonComputation,
    account_db_class=EmulatorAccountDB,
)
MySpuriousDragonVM = SpuriousDragonVM.configure(
    __name__='MySpuriousDragonVM',
    _state_class=MySpuriousDragonState,
)

# BYZANTIUM
MyByzantiumComputation = ByzantiumComputation.configure(
    __name__='MyByzantiumComputation',
    apply_computation=my_apply_computation,
)
MyByzantiumState = ByzantiumState.configure(
    __name__='MyByzantiumState',
    computation_class=MyByzantiumComputation,
    account_db_class=EmulatorAccountDB,
)
MyByzantiumVM = ByzantiumVM.configure(
    __name__='MyByzantiumVM',
    _state_class=MyByzantiumState,
)

# PETERSBURG
MyPetersburgComputation = PetersburgComputation.configure(
    __name__='MyPetersburgComputation',
    apply_computation=my_apply_computation,
)
MyPetersburgState = PetersburgState.configure(
    __name__='MyPetersburgState',
    computation_class=MyPetersburgComputation,
    account_db_class=EmulatorAccountDB,
)
MyPetersburgVM = PetersburgVM.configure(
    __name__='MyPetersburgVM',
    _state_class=MyPetersburgState,
)

# ISTANBUL
MyIstanbulComputation = IstanbulComputation.configure(
    __name__='MyIstanbulComputation',
    apply_computation=my_apply_computation,
)
MyIstanbulState = IstanbulState.configure(
    __name__='MyIstanbulState',
    computation_class=MyIstanbulComputation,
    account_db_class=EmulatorAccountDB,
)
MyIstanbulVM = IstanbulVM.configure(
    __name__='MyIstanbulVM',
    _state_class=MyIstanbulState
)

# MUIR_GLACIER
MyMuirGlacierComputation = MuirGlacierComputation.configure(
    __name__='MyMuirGlacierComputation',
    apply_computation=my_apply_computation,
)
MyMuirGlacierState = MuirGlacierState.configure(
    __name__='MyMuirGlacierState',
    computation_class=MyMuirGlacierComputation,
    account_db_class=EmulatorAccountDB,
)
MyMuirGlacierVM = MuirGlacierVM.configure(
    __name__='MyMuirGlacierVM',
    _state_class=MyMuirGlacierState
)

# BERLIN
"""MyBerlinComputation = BerlinComputation.configure(
    __name__='MyBerlinComputation',
    apply_computation=my_apply_computation,
)
MyBerlinState = BerlinState.configure(
    __name__='MyBerlinState',
    computation_class=MyBerlinComputation,
    account_db_class=EmulatorAccountDB,
)
MyBerlinVM = BerlinVM.configure(
    __name__='MyBerlinVM',
    _state_class=MyBerlinState
)"""
