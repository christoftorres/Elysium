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
 * @source: http://blockchain.unica.it/projects/ethereum-survey/attacks.html#simpledao
 * @author: -
 * @vulnerable_at_lines: 19
 */



contract SimpleDAO  is sGuard {
  mapping (address => uint) public credit;

  function donate(address to) payable {
    credit[to] = add_uint256(credit[to], msg.value);
  }

   function withdraw(uint amount) nonReentrant_  {
    if (credit[msg.sender]>= amount) {
      // <yes> <report> REENTRANCY
      bool res = msg.sender.call.value(amount)();
      credit[msg.sender] = sub_uint256(credit[msg.sender], amount);
    }
  }

  function queryCredit(address to) returns (uint){
    return credit[to];
  }
}
