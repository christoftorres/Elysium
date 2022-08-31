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
 * @source: https://github.com/sigp/solidity-security-blog
 * @author: Suhabe Bugrara
 * @vulnerable_at_lines: 27
 */

//added 


contract EtherStore  is sGuard {

    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;

     function depositFunds() nonReentrant_  public payable {
        balances[msg.sender] = add_uint256(balances[msg.sender], msg.value);
    }

     function withdrawFunds (uint256 _weiToWithdraw) nonReentrant_  public {
        require(balances[msg.sender] >= _weiToWithdraw);
        // limit the withdrawal
        require(_weiToWithdraw <= withdrawalLimit);
        // limit the time allowed to withdraw
        require(now >= add_uint256(lastWithdrawTime[msg.sender], 1 weeks));
        // <yes> <report> REENTRANCY
        require(msg.sender.call.value(_weiToWithdraw)());
        balances[msg.sender] = sub_uint256(balances[msg.sender], _weiToWithdraw);
        lastWithdrawTime[msg.sender] = now;
    }
 }
