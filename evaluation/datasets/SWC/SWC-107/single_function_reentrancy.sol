pragma solidity ^0.4.24;

contract SingleFunctionReentrancy {

  mapping (address => uint) private userBalances;

  function withdrawBalance() public {
      uint amountToWithdraw = userBalances[msg.sender];
      (bool success, ) = msg.sender.call.value(amountToWithdraw)(""); // At this point, the caller's code is executed, and can call withdrawBalance again
      require(success);
      userBalances[msg.sender] = 0;
  }
}
