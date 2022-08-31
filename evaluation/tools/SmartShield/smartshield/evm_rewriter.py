import argparse
import logging
import re
import json
import time
import signal
import contract
import patch
import restore
import miscellaneous


def remove_swarm_hash(evm):
    """
    Remove swarm hash from raw evm bytecode string
    """
    pattern = re.compile(r'a165627a7a72305820\w{64}0029$', re.A)
    if pattern.search(evm):
        evm = evm[:-86]
    return evm


def resolve_metadata(data):
    """
    Resolve vulnerability metadata
    """
    reentrancy = set()
    if 'Reentrancy' in data:
        for vul in data['Reentrancy']:
            call = vul['callOffset']
            sstore = vul['sStoreOffset']
            reentrancy.add((call, sstore))

    miscellany = {}
    if 'IntegerBugs' in data:
        for vul in data['IntegerBugs']:
            miscellany[vul['offset']] = vul['category']
    if 'UnhandledExceptions' in data:
        for vul in data['UnhandledExceptions']:
            miscellany[vul['offset']] = 'ue'

    return reentrancy, miscellany


def timeout_handler(_signum, _frame):
    """
    Handler function for timeout signal
    """
    raise RuntimeError('Timeout.')


def generate_report(report, file):
    """
    Generate patching report file
    """
    if file is not None:
        with open(file, 'w') as f:
            json.dump(report, f, indent=4)


def main():
    """
    Program entry
    """
    parser = argparse.ArgumentParser(description='An EVM ByteCode Patcher')
    parser.add_argument('-b', '--bytecode',
                        type=str, required=True, help='EVM bytecode file (HEX)')
    parser.add_argument('-m', '--metadata',
                        type=str, required=True, help='Vulnerability metadata file (JSON)')
    parser.add_argument('-t', '--timeout',
                        type=int, default=60,
                        help='Timeout for analyzing and patching in seconds (default to 60 seconds)')
    parser.add_argument('-o', '--output',
                        type=str, required=True, help='Patched EVM bytecode file (HEX)')
    parser.add_argument('-r', '--report',
                        type=str, help='Patching report file (JSON)')
    parser.add_argument('-d', '--debug',
                        action='store_true', help='Debug output')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    with open(args.bytecode) as f:
        raw_evm = f.read().strip()
        evm = bytes.fromhex(remove_swarm_hash(raw_evm))

    with open(args.metadata) as f:
        metadata = json.load(f)
        reentrancy, miscellany = resolve_metadata(metadata)

    report = {
        'Error': None,
        'Timeout': False,
        'Finished': False,
        'Time': None,
        'Reentrancy': [],
        'IntegerBugs': [],
        'UnhandledExceptions': []
    }

    start = time.time()
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(args.timeout)

    try:
        #
        # Initialize contract analysis, create DFG and CFG
        #
        contr, dfg, cfg = contract.initialize(evm)

        #
        # Analyze contract, construct DFG and CFG
        #
        trace, relocate = contract.analyze(contr, dfg, cfg)

        #
        # Patch reentrancy
        #
        patches = patch.execute(dfg, trace, reentrancy, report)

        #
        # Restore patched contract to bytecode
        #
        bytecode, miscellany = restore.execute(contr, dfg, relocate, patches, miscellany)

        #
        # Patch integer bugs and unhandled exceptions
        #
        miscellaneous.execute(contr, relocate, bytecode, miscellany, report)
    except Exception as e:
        end = time.time()
        if callable(getattr(signal, 'alarm', None)):
            signal.alarm(0)

        if str(e).strip('\'') == 'Timeout.':
            report['Timeout'] = True
        else:
            report['Error'] = str(e).strip('\'')
        report['Time'] = end - start
        generate_report(report, args.report)
        raise e

    end = time.time()
    if callable(getattr(signal, 'alarm', None)):
        signal.alarm(0)

    print('[*] Time Used: {:.5f} seconds'.format(end - start))

    report['Finished'] = True
    report['Time'] = end - start
    generate_report(report, args.report)

    with open(args.output, 'w') as f:
        f.write(bytecode.hex())


if __name__ == '__main__':
    main()
