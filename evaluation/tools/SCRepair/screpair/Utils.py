"""
@author: Xiao Liang Yu
"""
import attr
from typing import Sequence, Optional
from .IN import CodeRange
from abc import ABC
from logbook import Logger
import os

logger = Logger(os.path.basename(__file__))


@attr.s(auto_attribs=True, frozen=True, kw_only=True)
class FaultElement(ABC):
    weigh: Optional[int] = None

    def toSpecifierStr(self) -> str:
        raise NotImplementedError()


@attr.s(auto_attribs=True, frozen=True, kw_only=True)
class FaultElement_CodeRange(FaultElement):
    codeRange: CodeRange

    def toSpecifierStr(self) -> str:
        return 'LOC:{start_line}{start_column}-{end_line}{end_column}{str_weigh}'.format(
            start_line=self.codeRange.start.line,
            start_column=F",{self.codeRange.start.column}"
            if self.codeRange.start.column is not None else '',
            end_line=self.codeRange.end.line,
            end_column=F",{self.codeRange.end.column}"
            if self.codeRange.end.column is not None else '',
            str_weigh=F'(({self.weigh}))' if self.weigh is not None else '',
        )


@attr.s(auto_attribs=True, frozen=True, kw_only=True)
class FaultElement_NodeType(FaultElement):
    nodeType: str
    contractName: Optional[str] = None
    functionName: Optional[str] = attr.ib(default=None)

    @functionName.validator
    def __functionNameValidator(self, attribute, value):
        if value is not None and self.contractName is None:
            raise ValueError(F'functionName must be None when contractName is None')

    def toSpecifierStr(self) -> str:
        str_weigh = F'(({self.weigh}))' if self.weigh is not None else ''

        if self.contractName is not None:
            if self.functionName is not None:
                str_body = F'{self.contractName}.{self.functionName}-{self.nodeType}'
            else:
                str_body = F'{self.contractName}-{self.nodeType}'
        else:
            str_body = self.nodeType
        
        return F'TYPE:{str_body}{str_weigh}'


@attr.s(auto_attribs=True, frozen=False)
class FaultLocalization(object):

    faultElements: Sequence[FaultElement]

    def __repr__(self) -> str:
        return self.toSpecifierStr()

    def toSpecifierStr(self) -> str:

        rstStr = [
            ele.toSpecifierStr()
            for ele in sorted(frozenset(self.faultElements), key=lambda x: (type(x).__name__, x))
        ]
        return ';'.join(rstStr)

from distutils.util import strtobool

def strToBool(val: str) -> bool:
    return bool(strtobool(val))

from typing import Optional, Tuple, Iterable, Any
from itertools import combinations, chain

def powerset(iterable: Iterable[Any]):
    """
    Note: This results a generator
    """
    s = tuple(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))

