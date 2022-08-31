#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .evm import EVM

class Emulator:
    def __init__(self, provider, block, debug=False):
        self._evm = EVM(debug)
        self._evm.set_vm(provider, block)

    def create_snapshot(self):
        self._evm.create_snapshot()

    def restore_from_snapshot(self):
        self._evm.restore_from_snapshot()

    def prepare_state(self, transaction, consider_all_transactions=False):
        return self._evm.prepare_state(transaction, consider_all_transactions)

    def send_transaction(self, transaction, code=None, gas_limit=None):
        return self._evm.deploy_transaction(transaction, code, gas_limit)
