import itertools

from ..cfg.function import Function

BASIC_BLOCK_END = ['STOP',
                   'SELFDESTRUCT',
                   'RETURN',
                   'REVERT',
                   'INVALID',
                   'SUICIDE',
                   'JUMP',
                   'JUMPI',
                   'ASSERTFAIL']

class AbsStackElem(object):
    '''Represent an element of the stack

    An element is a set of potential values.
    There are at max MAXVALS number of values, otherwise it is set to TOP

    TOP is representented as None

    []     --> [1, 2, None, 3...]  --> None
    Init   --> [ up to 10 vals ]   --  TOP

    If a value is not known, it is None.
    Note that we make the difference between the list beeing TOP, and one
    of the value inside the list beeing TOP. The idea is that even if one
    of the value is not known, we can list keep track of the known values.

    Thus our analysis is an under-approximation of an over-approximation
    and is not sound.
    '''



    def __init__(self, auhtorized_values):
        self._vals = set()
        self._authorized_values = auhtorized_values

        # Maximum number of values inside the set. If > MAXVALS -> TOP
        self._max_number_of_elements = 100
        if self._authorized_values:
            # If we know the set of targets, we can change the max number of elements in the set
            self._max_number_of_elements = len(auhtorized_values)


    @property
    def authorized_values(self):
        return self._authorized_values

    def append(self, nbr):
        '''
            Append value to the element

        Args:
            nbr (int, None)
        '''
        # Optimization enabled
        if self._authorized_values:
            # Only keep track of values that are JMPDEST
            if nbr in self._authorized_values:
                self._vals.add(nbr)
            # Only Add None if its not present; avoid the list to grow up on unknown values
            elif None not in self._authorized_values:
                self._vals.add(None)
        else:
            self._vals.add(nbr)

    def get_vals(self):
        '''
            Return the values. The return must be checked for TOP (None)

        Returns:
            set of int, or None
        '''
        return self._vals

    def set_vals(self, vals):
        '''
            Set the values
        Args:
            vals (set of int, or None): List of values, or TOP
        '''
        self._vals = vals

    def absAnd(self, elem):
        '''
            AND between two AbsStackElem
        Args:
            elem (AbsStackElem)
        Returns:
            AbsStackElem: New object containing the result of the AND between
            the values. If one of the absStackElem is TOP, returns TOP
        '''
        newElem = AbsStackElem(self.authorized_values)
        v1 = self.get_vals()
        v2 = elem.get_vals()
        if v1 is None or v2 is None:
            newElem.set_vals(None)
            return newElem

        for (a, b) in itertools.product(v1, v2):
            if a is None or b is None:
                newElem.append(None)
            else:
                newElem.append(a & b)

        return newElem

    def merge(self, elem):
        '''
            Merge between two AbsStackElem
        Args:
            elem (AbsStackElem)
        Returns:
            AbsStackElem: New object containing the result of the merge
                          If one of the absStackElem is TOP, returns TOP
        '''
        newElem = AbsStackElem(self.authorized_values)
        v1 = self.get_vals()
        v2 = elem.get_vals()
        if v1 is None or v2 is None:
            newElem.set_vals(None)
            return newElem
        vals = set(v1 | v2)
        if len(vals) > self._max_number_of_elements:
            vals = None
        newElem.set_vals(vals)
        return newElem

    def equals(self, elems):
        '''
            Return True if equal

        Args:
            elem (AbsStackElem)
        Returns:
            bool: True if the two absStackElem are equals. If both are TOP
            returns True
        '''

        v1 = self.get_vals()
        v2 = elems.get_vals()

        return v1 == v2

    def get_copy(self):
        '''
            Return of copy of the object
        Returns:
            AbsStackElem
        '''
        cp = AbsStackElem(self.authorized_values)
        cp.set_vals(self.get_vals())
        return cp

    def __str__(self):
        '''
            String representation
        Returns:
            str
        '''
        return str(self._vals)


class Stack(object):
    '''
        Stack representation
        The stack is updated throyugh the push/pop/dup operation, and returns
        itself
        We keep the same stack for one basic block, to reduce the memory usage
    '''

    def __init__(self, authorized_values):
        self._elems = []
        self._authorized_values = authorized_values

    @property
    def authorized_values(self):
        return self._authorized_values

    def copy_stack(self, stack):
        '''
            Copy the given stack

        Args:
            Stack: stack to copy
        '''
        self._elems = [x.get_copy() for x in stack.get_elems()]

    def push(self, elem):
        '''
            Push an elem. If the elem is not an AbsStackElem, create a new
            AbsStackElem
        Args:
            elem (AbsStackElem, or str or None): If str, it should be the
            hexadecimal repr
        '''
        if not isinstance(elem, AbsStackElem):
            st = AbsStackElem(self.authorized_values)
            st.append(elem)
            elem = st

        self._elems.append(elem)

    def insert(self, elem):
        if not isinstance(elem, AbsStackElem):
            st = AbsStackElem(self.authorized_values)
            st.append(elem)
            elem = st

        self._elems.insert(0, elem)


    def pop(self):
        '''
            Pop an element.
        Returns:
            AbsStackElem
        '''
        if not self._elems:
            self.push(None)

        return self._elems.pop()

    def swap(self, n):
        '''
            Swap operation
        Args:
            n (int)
        '''
        if len(self._elems) >= (n+1):
            elem = self._elems[-1-n]
            top = self.top()
            self._elems[-1] = elem
            self._elems[-1-n] = top

        # if we swap more than the size of the stack,
        # we can assume that elements are missing on the stack
        else:
            top = self.top()
            missing_elems = n - len(self._elems) + 1
            for _ in range(0, missing_elems):
                self.insert(None)
            self._elems[-1-n] = top

    def dup(self, n):
        '''
            Dup operation
        '''
        if len(self._elems) >= n:
            self.push(self._elems[-n])
        else:
            self.push(None)

    def get_elems(self):
        '''
            Returns the stack elements
        Returns:
            List AbsStackElem
        '''
        return self._elems

    def set_elems(self, elems):
        '''
            Set the stack elements
        Args:
            elems (list of AbsStackElem)
        '''
        self._elems = elems

    def merge(self, stack):
        '''
            Merge two stack. Returns a new object
        Arg:
            stack (Stack)
        Returns: New object representing the merge
        '''
        newSt = Stack(self.authorized_values)
        elems1 = self.get_elems()
        elems2 = stack.get_elems()
        # We look for the longer stack
        if len(elems2) <= len(elems1):
            longStack = elems1
            shortStack = elems2
        else:
            longStack = elems2
            shortStack = elems1
        longStack = [x.get_copy() for x in longStack]
        # Merge elements
        for i in range(0, len(shortStack)):
            longStack[-(i+1)] = longStack[-(i+1)].merge(shortStack[-(i+1)])
        newSt.set_elems(longStack)
        return newSt

    def equals(self, stack):
        '''
            Test equality between two stack
        Args:
            stack (Stack)
        Returns:
            bool: True if the stacks are equals
        '''
        elems1 = self.get_elems()
        elems2 = stack.get_elems()
        if len(elems1) != len(elems2):
            return False
        for (v1, v2) in zip(elems1, elems2):
            if not v1.equals(v2):
                return False
        return True

    def top(self):
        '''
            Return the element at the top (without pop)
        Returns:
            AbsStackElem
        '''
        if not self._elems:
            self.push(None)
        return self._elems[-1]

    def __str__(self):
        '''
            String representation (only first 5 items)
        '''
        return str([str(x) for x in self._elems[-100::]])


def get_valid_destination(instructions):
    '''
    Return the list of valid destinations
    :param instructions:
    :return:
    '''
    return set([ins.pc for ins in instructions if ins.name == 'JUMPDEST'])

class StackValueAnalysis(object):
    '''Stack value analysis.

    After each convergence, we add the new branches and re-analyze the function.
    The exploration is bounded in case the analysis is lost.

    IF enable_optimization is enabled, only keep track of valid destination
    '''

    def __init__(self,
                 cfg,
                 entry_point,
                 key,
                 maxiteration=1000,
                 maxexploration=100,
                 initStack=None,
                 enable_optimization=True,
                 symbolic_stack_analysis=True):
        '''
        Args:
            maxiteration (int): number of time re-analyze the function
            maxexploration (int): number of time re-explore a bb
        '''
        # last targets discovered. We keep track of these branches to only
        # re-launch the analysis on new paths found
        self.last_discovered_targets = {}

        # all the targets discovered
        self.all_discovered_targets = {}
        self.stacksIn = {}
        self.stacksOut = {}

        # bb counter, to bound the bb exploration
        self.bb_counter = {}

        # number of time the function was analysis, to bound the analysis
        # recursion
        self.counter = 0

        # limit the number of time we re-analyze a function
        self.MAXITERATION = maxiteration

        # limit the number of time we explore a basic block (unrool)
        self.MAXEXPLORATION = maxexploration

        self.initStack = initStack

        self._entry_point = entry_point

        self.cfg = cfg

        self._key = key

        self._basic_blocks_explored = []

        self._to_explore = {self._entry_point}

        self._outgoing_basic_blocks = []

        self._authorized_values = None

        if enable_optimization:
            self._authorized_values = get_valid_destination(cfg.instructions)

        self._symbolic_stack_analysis = symbolic_stack_analysis

    @property
    def authorized_values(self):
        return self._authorized_values

    def is_jumpdst(self, addr):
        '''
            Check that an instruction is a JUMPDEST
            A JUMP to no-JUMPDEST instruction is not valid (see yellow paper).
            Yet some assembly tricks use a JUMP to an invalid instruction to
            trigger THROW. We need to filter those jumps
        Args:
            addr (int)
        Returns:
            bool: True if the instruction is a JUMPDEST
        '''
        ins = self.cfg.get_instruction_at(addr)
        if ins is None:
            return False

        return ins.name == 'JUMPDEST'

    def stub(self, ins, addr, stack):
        return (False, None)

    def _transfer_func_ins(self, ins, addr, stackIn):
        stack = Stack(self.authorized_values)
        stack.copy_stack(stackIn)

        (is_stub, stub_ret) = self.stub(ins, addr, stack)
        if is_stub:
            return stub_ret

        op = ins.name
        if op.startswith('PUSH'):
            stack.push(ins.operand)

        elif op.startswith('SWAP'):
            nth_elem = int(op[4:])
            stack.swap(nth_elem)
        elif op.startswith('DUP'):
            nth_elem = int(op[3:])
            stack.dup(nth_elem)
        elif op == 'AND':
            v1 = stack.pop()
            v2 = stack.pop()
            stack.push(v1.absAnd(v2))
        # For all the other opcode: remove
        # the pop elements, and push None elements
        # if JUMP or JUMPI saves the last value before poping
        else:
            n_pop = ins.pops
            n_push = ins.pushes
            for _ in range(0, n_pop):
                stack.pop()
            for _ in range(0, n_push):
                stack.push(None)

        return stack

    def _explore_bb(self, bb, stack):
        '''
            Update the stack of a basic block. Return the last jump/jumpi
            target

            The last jump value is returned, as the JUMP/JUMPI instruction will
            pop the value before returning the function

            self.stacksOut will contain the stack of last instruction of the
            basic block.
        Args:
            bb
            stack (Stack)
        Returns:
            AbsStackElem: last jump computed.
        '''
        last_jump = None

        if not bb.start.pc in self._basic_blocks_explored:
            self._basic_blocks_explored.append(bb.start.pc)

        ins = None
        for ins in bb.instructions:
            addr = ins.pc
            self.stacksIn[addr] = stack
            stack = self._transfer_func_ins(ins, addr, stack)

            self.stacksOut[addr] = stack

        if ins:
            # if we are going to do a jump / jumpi
            # get the destination
            op = ins.name
            if op == 'JUMP' or op == 'JUMPI':
                last_jump = stack.top()
        return last_jump

    def _transfer_func_bb(self, bb, init=False):
        '''
            Transfer function
        '''

        if self._key == Function.DISPATCHER_ID and bb.reacheable:
            return
        addr = bb.start.pc
        end_ins = bb.end
        end = end_ins.pc

        # bound the number of times we analyze a BB
        if addr not in self.bb_counter:
            self.bb_counter[addr] = 1
        else:
            self.bb_counter[addr] += 1

            if self.bb_counter[addr] > self.MAXEXPLORATION:
                #print('Reach max explo {}'.format(hex(addr)))
                return

        # Check if the bb was already analyzed (used for convergence)
        if end in self.stacksOut:
            prev_stack = self.stacksOut[end]
        else:
            prev_stack = None


        if init and self.initStack:
            stack = self.initStack
        else:
            stack = Stack(self.authorized_values)

        # Merge all the stack incoming_basic_blocks
        # We merge only father that were already analyzed
        incoming_basic_blocks = bb.incoming_basic_blocks(self._key)

        incoming_basic_blocks = [f for f in incoming_basic_blocks if f.end.pc in self.stacksOut]

        if incoming_basic_blocks:
            father = incoming_basic_blocks[0]
            incoming_basic_blocks = incoming_basic_blocks[1::]
            stack.copy_stack(self.stacksOut[father.end.pc])
            for father in incoming_basic_blocks:
                stack = stack.merge(self.stacksOut[father.end.pc])
        # Analyze the BB
        self._explore_bb(bb, stack)

        # check if the last instruction is a JUMP
        op = end_ins.name

        if op == 'JUMP':
            src = end
            dst = self.stacksIn[end].top().get_vals()
            if dst:
                dst = [x for x in dst if x and self.is_jumpdst(x)]
                if not dst:
                    if self._symbolic_stack_analysis:
                        symbolic_stack = self.perform_symbolic_stack_analysis(bb)
                        if symbolic_stack and not symbolic_stack[-1] is None:
                            dst = [symbolic_stack[-1]]
                            self.add_branches(src, dst)
                    else:
                        self.add_branches(src, dst)
                else:
                    self.add_branches(src, dst)

        elif op == 'JUMPI':
            src = end
            dst = self.stacksIn[end].top().get_vals()
            if dst:
                dst = [x for x in dst if x and self.is_jumpdst(x)]
                if not dst:
                    if self._symbolic_stack_analysis:
                        symbolic_stack = self.perform_symbolic_stack_analysis(bb)
                        if symbolic_stack and not symbolic_stack[-1] is None:
                            dst = [symbolic_stack[-1]]
                            self.add_branches(src, dst)
                    else:
                        self.add_branches(src, dst)
                else:
                    self.add_branches(src, dst)

        # check for convergence
        converged = False

        if prev_stack:
            if prev_stack.equals(self.stacksOut[end]):
                converged = True

        if not converged:
            new_outgoing_basic_blocks = bb.outgoing_basic_blocks(self._key)
            self._outgoing_basic_blocks = new_outgoing_basic_blocks + self._outgoing_basic_blocks

    def add_branches(self, src, dst):
        '''
            Add new branches
        Ags:
            src (int)
            dst (list of int)
        '''
        if src not in self.all_discovered_targets:
            self.all_discovered_targets[src] = set()

        for d in dst:
            if d not in self.all_discovered_targets[src]:
                if src not in self.last_discovered_targets:
                    self.last_discovered_targets[src] = set()

                self.last_discovered_targets[src].add(d)

                self.all_discovered_targets[src].add(d)

    def explore(self):
        """
            Launch the analysis
        """
        init = False

        bb = self._to_explore.pop()

        if bb:
            if self._symbolic_stack_analysis:
                # --- First explore jumps with static jump addresses ---
                if bb.end.name == "JUMPI" or bb.end.name == "JUMP":
                    previous_all_outgoing_basic_blocks = bb.all_outgoing_basic_blocks
                    symbolic_stack = self.perform_symbolic_stack_analysis(bb)
                    if symbolic_stack and not symbolic_stack[-1] is None:
                        if bb.end.name == "JUMPI":
                            # True branch
                            dst = symbolic_stack[-1]
                            bb_to = self.cfg.get_basic_block_at(dst)
                            if bb_to:
                                bb.add_outgoing_basic_block(bb_to, self._key)
                                bb_to.add_incoming_basic_block(bb, self._key)
                                if bb.all_outgoing_basic_blocks != previous_all_outgoing_basic_blocks:
                                    self._to_explore.add(bb_to)
                                # False branch
                                dst = bb.end.pc + 1
                                bb_to = self.cfg.get_basic_block_at(dst)
                                bb.add_outgoing_basic_block(bb_to, self._key)
                                bb_to.add_incoming_basic_block(bb, self._key)
                                if bb.all_outgoing_basic_blocks != previous_all_outgoing_basic_blocks:
                                    self._to_explore.add(bb_to)
                        else:
                            dst = symbolic_stack[-1]
                            bb_to = self.cfg.get_basic_block_at(dst)
                            if bb_to:
                                bb.add_outgoing_basic_block(bb_to, self._key)
                                bb_to.add_incoming_basic_block(bb, self._key)
                                if bb.all_outgoing_basic_blocks != previous_all_outgoing_basic_blocks:
                                    self._to_explore.add(bb_to)
                # ------------------------------------------------------

            self._transfer_func_bb(bb, init)

        while self._outgoing_basic_blocks:
            self._transfer_func_bb(self._outgoing_basic_blocks.pop())

        last_discovered_targets = self.last_discovered_targets
        self.last_discovered_targets = {}

        for src, dsts in last_discovered_targets.items():
            bb_from = self.cfg.get_basic_block_at(src)
            for dst in dsts:
                bb_to = self.cfg.get_basic_block_at(dst)
                if bb_to:
                    bb_from.add_outgoing_basic_block(bb_to, self._key)
                    bb_to.add_incoming_basic_block(bb_from, self._key)

        dsts = [dests for (src, dests) in last_discovered_targets.items()]
        self._to_explore |= {
            self.cfg.get_basic_block_at(item)
            for sublist in dsts
            for item in sublist
        }

    def perform_symbolic_stack_analysis(self, basic_block):
        stack = list()
        for i in basic_block.instructions:
            if i.name.startswith("PUSH"):
                stack.append(i.operand)
            elif i.name.startswith("DUP"):
                n = int(i.name[3:])
                if len(stack) >= n:
                    stack.append(stack[-n])
                else:
                    stack.append(None)
            elif i.name.startswith("SWAP"):
                n = int(i.name[4:])
                if len(stack) > 0:
                    if len(stack) >= (n+1):
                        elem = stack[-1-n]
                        top = stack[-1]
                        stack[-1] = elem
                        stack[-1-n] = top
                    # if we swap more than the size of the stack,
                    # we can assume that elements are missing on the stack
                    else:
                        top = stack[-1]
                        missing_elems = n - len(stack) + 1
                        for _ in range(0, missing_elems):
                            stack.insert(0, None)
                        elem = stack[-1-n]
                        stack[-1] = elem
                        stack[-1-n] = top
            elif i.name == "AND":
                try:
                    a = stack.pop()
                except:
                    a = None
                try:
                    b = stack.pop()
                except:
                    b = None
                if a is None or b is None:
                    stack.append(None)
                else:
                    stack.append(a & b)
            elif i.name in ["JUMP", "JUMPI"]:
                return stack
            else:
                for _ in range(i.pops):
                    try:
                        stack.pop()
                    except:
                        pass
                for _ in range(i.pushes):
                    stack.append(None)
        return stack

    def analyze(self):
        self.cfg.compute_simple_edges(self._key)
        while self._to_explore:
            self.explore()

        self.cfg.compute_reachability(self._entry_point, self._key)

        return self._basic_blocks_explored
