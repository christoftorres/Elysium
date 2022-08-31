contract sGuard{
  function sub_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }
  
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
 * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-105#wallet-03-wrong-constructorsol
 * @author: -
 * @vulnerable_at_lines: 19,20
 */

 

 /* User can add pay in and withdraw Ether.
    The constructor is wrongly named, so anyone can become 'creator' and withdraw all funds.
 */

 contract Wallet  is sGuard {
     address creator;

     mapping(address => uint256) balances;
     
     // <yes> <report> ACCESS_CONTROL
     function initWallet() public {
         creator = msg.sender;
     }

      function deposit() nonReentrant_  public payable {
         assert(add_uint256(balances[msg.sender], msg.value) > balances[msg.sender]);
         balances[msg.sender] = add_uint256(balances[msg.sender], msg.value);
     }

      function withdraw(uint256 amount) nonReentrant_  public {
         require(amount <= balances[msg.sender]);
         msg.sender.transfer(amount);
         balances[msg.sender] = sub_uint256(balances[msg.sender], amount);
     }

     // In an emergency the owner can migrate  allfunds to a different address.

     function migrateTo(address to) public {
         require(creator == msg.sender);
         to.transfer(this.balance);
     }

 }
