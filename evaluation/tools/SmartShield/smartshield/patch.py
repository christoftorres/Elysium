import logging

log = logging.getLogger(__name__)


def slicing(source, call, dfg, sequence, discarded):
    """
    Slicing contract from source instruction based on data flow dependencies, construct instruction sequence, record
    further memory/storage dependencies
    """
    slices = []
    deps = set()
    overs = set()
    trv_stack = [source]
    visited = {node: False for node in dfg.graph.nodes()}
    nodes = dfg.graph.nodes()
    discarded.add(source)

    while len(trv_stack) > 0:
        instr = trv_stack[0]
        # Instruction visited or not
        if visited[instr]:
            visited[instr] = False
            slices.append(instr)
            trv_stack.pop(0)
        else:
            visited[instr] = True
            
            # Check patching feasibility considering data flow dependencies
            if instr == call:
                raise RuntimeError('Violating data flow dependencies. CALL: {:#x}, lift: {:#x}'.format(call, instr))

            # Label discarded instructions, remove later
            if not nodes[instr]['instr'].reserved:
                for suc in dfg.graph[instr]:
                    if suc not in discarded:
                        break
                else:
                    discarded.add(instr)

            # Record further memory/storage dependencies
            for dep in nodes[instr]['instr'].dependence:
                if dep in sequence:
                    deps.add(dep)

            # Record memory/storage overwrites
            overs.update(nodes[instr]['instr'].overwrite)

            # Advance slicing
            for pre in dfg.graph.predecessors(instr):
                if visited[pre]:
                    raise RuntimeError('Error slicing, loop detected. lift: {:#x}, pre: {:#x}'.format(instr, pre))
                trv_stack.insert(0, pre)

    return slices, deps, overs


def lifting(sstore, call, dfg, trace, sliced, lifted, discarded):
    """
    Lift and slice SSTORE and its memory/storage dependencies iteratively
    """
    if (call, sstore) not in trace:
        raise KeyError('Error tracing executed instructions from CALL to SSTORE. CALL: {:#x}, SSTORE: {:#x}'
                       .format(call, sstore))
    lift_stack = [sstore]
    sequence = trace[(call, sstore)]
    nodes = dfg.graph.nodes()
    lifts = set()
    overwrites = set()
    dependencies = set()

    while len(lift_stack) > 0:
        instr = lift_stack.pop(0)

        # Check patching feasibility considering control flow dependencies
        if nodes[call]['instr'].layer != nodes[instr]['instr'].layer:
            raise RuntimeError('Violating control flow dependencies. CALL: {:#x}, lift: {:#x}'.format(call, instr))

        # Check patching feasibility considering CALL, CALLCODE, DELEGATECALL and STATICCALL
        name = nodes[instr]['instr'].name
        if name == 'CALL' or name == 'CALLCODE' or name == 'DELEGATECALL' or name == 'STATICCALL':
            raise RuntimeError('Cannot lift CALL, CALLCODE, DELEGATECALL or STATICCALL. CALL: {:#x}, lift: {:#x}'
                               .format(call, instr))

        # Slicing contract from source instruction based on data flow dependencies
        slices, deps, overs = slicing(instr, call, dfg, sequence, discarded)
        lifts.update(slices)
        overwrites.update(overs)
        if instr not in sliced:
            sliced[instr] = slices

        # Record and merge lifted instructions
        if instr not in lifted:
            lifted[instr] = {call: sequence}
        else:
            if call not in lifted[instr]:
                for pos in dict(lifted[instr]):
                    if call in lifted[instr][pos]:
                        break
                    elif pos in sequence:
                        lifted[instr][call] = sequence
                        del lifted[instr][pos]
                        break
                else:
                    lifted[instr][call] = sequence

        # Lift iteratively
        for dep in deps:
            lift_stack.insert(0, dep)

    # Check patching feasibility considering memory/storage dependencies
    for instr in sequence.difference(lifts):
        dependencies.update(nodes[instr]['instr'].dependence)
    if len(overwrites.intersection(dependencies)) > 0:
        raise RuntimeError('Violating memory/storage dependencies. CALL: {:#x}, SSTORE: {:#x}'.format(call, sstore))


def set_report(report, call, sstore, msg):
    """
    Set patching report file
    """
    report['Reentrancy'].append(
        {
            'callOffset': call,
            'sStoreOffset': sstore,
            'result': msg
        }
    )


def execute(dfg, trace, reentrancy, report):
    """
    Patch reentrancy
    """
    # Lift and slice SSTORE and its memory/storage dependencies iteratively
    sliced = {}
    lifted = {}
    discarded = set()
    for vul in reentrancy:
        call = vul[0]
        sstore = vul[1]
        old_sliced = sliced.copy()
        old_lifted = lifted.copy()
        old_discarded = discarded.copy()
        try:
            lifting(sstore, call, dfg, trace, sliced, lifted, discarded)
        except Exception as e:
            if str(e).strip('\'') == 'Timeout.':
                raise e
            else:
                sliced = old_sliced
                lifted = old_lifted
                discarded = old_discarded
                set_report(report, call, sstore, str(e).strip('\''))
        else:
            set_report(report, call, sstore, 'Done.')

    # Label discarded instructions, remove later
    nodes = dfg.graph.nodes()
    for instr in discarded:
        nodes[instr]['instr'].discarded = True

    # Resolve patches
    patches = {}
    for instr in lifted:
        for pos in lifted[instr]:
            if pos not in patches:
                patches[pos] = {}
            patches[pos][instr] = sliced[instr]

    return patches
