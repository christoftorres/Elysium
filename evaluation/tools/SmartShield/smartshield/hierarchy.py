import logging

log = logging.getLogger(__name__)


class StackElement:
    """
    Storage class, storing a structured element of traverse stack
    """
    def __init__(self, block, new, previous_layer):
        self.block = block
        self.new = new  # Create new layer or not
        self.previous_layer = previous_layer  # Layer of previous block


def set_layers(blk, layer):
    """
    Set block and instruction layers
    """
    blk.layer = layer
    for instr in blk.instructions:
        instr.layer = layer


def layering(contr, cfg):
    """
    Traverse CFG, create layers for basic blocks and instructions
    """
    cnt = 0
    init_blk = contr.blocks[0].offset
    trv_stack = [StackElement(init_blk, True, None)]
    nodes = cfg.graph.nodes()

    while len(trv_stack) > 0:
        cur_elm = trv_stack.pop(0)
        blk = cur_elm.block

        if nodes[blk]['blk'].layer is not None:
            # Pruning if layered already
            continue
        else:
            if cfg.graph.in_degree(blk) > 1:
                # Create new layer
                layer = cnt
                cnt += 1
            else:
                if cur_elm.new:
                    # Create new layer
                    layer = cnt
                    cnt += 1
                else:
                    # Hold old layer
                    layer = cur_elm.previous_layer

            # Set block and instruction layers
            set_layers(nodes[blk]['blk'], layer)

        # Advance layering
        hold_layer = False
        non_revert = None
        for next_blk in cfg.graph[blk]:
            trv_stack.insert(0, StackElement(next_blk, True, None))
            if not nodes[next_blk]['blk'].revert:
                if non_revert is None:
                    non_revert = trv_stack[0]
                    hold_layer = True
                else:
                    hold_layer = False
        if hold_layer:
            non_revert.new = False
            non_revert.previous_layer = layer
