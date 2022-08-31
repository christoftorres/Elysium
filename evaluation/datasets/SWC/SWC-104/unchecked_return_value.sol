pragma solidity ^0.4.24;

contract ReturnValue {

  function callnotchecked(address callee) public {
    callee.call();
  }
}
