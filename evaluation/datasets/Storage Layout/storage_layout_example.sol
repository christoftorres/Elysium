// SPDX-License-Identifier: UNLICENSED

contract A {
  uint256 x; // storage slot 0
  uint256 y; // storage slot 1
  uint256[100] z; // storage slots 2 - 101
  uint256 private a; // storage slot 102

  function set(uint index, uint value) public {
      z[index] = value;
  }

  function add(uint value) public {
      z[42] = value;
      z[13] = value;
      z[76] = value;
  }

  function setA(uint _a) public {
    a = _a;
  }

}
