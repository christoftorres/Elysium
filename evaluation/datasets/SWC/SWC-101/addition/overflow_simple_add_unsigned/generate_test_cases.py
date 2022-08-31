#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

def main():
    for i in range(0, 256, 8):
        with open("overflow_simple_add.sol", "r") as f:
            content = f.read()
            content = content.replace("uint ", "uint256 ")
            content = content.replace("uint256", "uint"+str(i+8))
            if not os.path.exists(str(i+8)):
                os.mkdir(str(i+8))
            with open(os.path.join(str(i+8), "overflow_simple_add.sol"), "w") as g:
                g.write(content)

if __name__ == '__main__':
    main()
