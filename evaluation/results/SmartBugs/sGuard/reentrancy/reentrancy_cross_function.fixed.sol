contract sGuard{
  function sub_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
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
  
  function add_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}
/*
 * @source: https://consensys.github.io/smart-contract-best-practices/known_attacks/
 * @author: consensys
 * @vulnerable_at_lines: 24
 */



contract Reentrancy_cross_function  is sGuard {

    // INSECURE
    mapping (address => uint) private userBalances;

     function transfer(address to, uint amount) nonReentrant_  {
        if (userBalances[msg.sender] >= amount) {
            userBalances[to] = add_uint256(userBalances[to], amount);
            userBalances[msg.sender] = sub_uint256(userBalances[msg.sender], amount);
        }
    }

     function withdrawBalance() nonReentrant_  public {
        uint amountToWithdraw = userBalances[msg.sender];
        // <yes> <report> REENTRANCY
        (bool success, ) = msg.sender.call.value(amountToWithdraw)(""); // At this point, the caller's code is executed, and can call transfer()
        require(success);
        userBalances[msg.sender] = 0;
    }
}
