import logging
import networkx as nx
# import matplotlib.pyplot as plt

log = logging.getLogger(__name__)


class DiGraph:
    """
    Directed Graph, storing
    + Data Flow Graph
        + node: instructions
            + attr: instr -- an instance of Instruction class, detailed information about instructions
        + edge: data flow dependencies between instructions
    + Control Flow Graph
        + node: basic blocks
            + attr: blk -- an instance of BasicBlock class, detailed information about basic blocks
        + edge: control flow dependencies between basic blocks
            + attr: type -- 'JUMPI', 'JUMP' or 'SEQUENTIAL', describing types of control flow dependencies
    """
    def __init__(self):
        self.graph = nx.DiGraph()

    # def draw(self):
    #     """
    #     TODO: Temporarily for debugging, remove this method later
    #     """
    #     g = self.graph
    #     plt.rcParams['figure.figsize'] = [16, 9]
    #     pos = nx.nx_agraph.pygraphviz_layout(g)
    #
    #     labels = {}
    #     for n, d in g.nodes(data=True):
    #         if 'instr' in d:
    #             labels[n] = format(n, 'x') + '(' + str(d['instr'].layer) + ')'
    #         elif 'blk' in d:
    #             labels[n] = format(n, 'x') + '(' + str(d['blk'].layer) + ')'
    #         else:
    #             labels[n] = format(n, 'x')
    #
    #     nx.draw_networkx_nodes(g, pos)
    #     nx.draw_networkx_labels(g, pos, labels=labels)
    #     nx.draw_networkx_edges(g, pos)
    #     plt.axis('off')
    #     plt.show()
