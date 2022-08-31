pragma solidity ^0.4.24;

contract Overflow_Add {

    int120 public balance = -1;

    function add(int120 deposit) public {
      balance += deposit;
    }

}
