pragma solidity ^0.4.24;

contract ReturnValue {

  function callchecked(address callee) public {
    require(callee.call());
  }
}
