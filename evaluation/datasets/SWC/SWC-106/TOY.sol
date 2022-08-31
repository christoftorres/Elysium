pragma solidity ^0.4.24;

contract TOY {

  address public owner;
  bool public FLAG;

  modifier checkOwner {
    require(msg.sender == owner);
    _;
  }

  function TOY() {
    owner = msg.sender;
  }

  function setFlag(bool newFlag) checkOwner public { 
    FLAG = newFlag;
  }

  function boom() public {
    selfdestruct(owner);
  }
}
