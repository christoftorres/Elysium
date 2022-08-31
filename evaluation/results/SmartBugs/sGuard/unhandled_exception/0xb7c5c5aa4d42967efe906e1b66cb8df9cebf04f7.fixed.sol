contract sGuard{
  function add_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
  
  bool internal locked_;
  constructor() internal {
    locked_ = false;
  }
  modifier nonReentrant_() {
    require(!locked_);
    locked_ = true;
    _;
    locked_ = false;
  }
}
/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 25
 */



/*
!!! THIS CONTRACT IS EXPLOITABLE AND FOR EDUCATIONAL PURPOSES ONLY !!!

This smart contract allows a user to (insecurely) store funds
in this smart contract and withdraw them at any later point in time
*/

contract keepMyEther  is sGuard {
    mapping(address => uint256) public balances;
    
    function () payable public {
        balances[msg.sender] = add_uint256(balances[msg.sender], msg.value);
    }
    
     function withdraw() nonReentrant_  public {
        // <yes> <report> UNCHECKED_LL_CALLS
        msg.sender.call.value(balances[msg.sender])();
        balances[msg.sender] = 0;
    }
}