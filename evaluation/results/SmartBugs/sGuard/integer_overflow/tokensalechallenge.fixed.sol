contract sGuard{
  function mul_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }
  
  function add_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
  
  function sub_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }
}
/*
 * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-101 // https://capturetheether.com/challenges/math/token-sale/
 * @author: Steve Marx
 * @vulnerable_at_lines: 23,25,33
 */



contract TokenSaleChallenge  is sGuard {
    mapping(address => uint256) public balanceOf;
    uint256 constant PRICE_PER_TOKEN = 1 ether;

    function TokenSaleChallenge(address _player) public payable {
        require(msg.value == 1 ether);
    }

    function isComplete() public view returns (bool) {
        return address(this).balance < 1 ether;
    }

    function buy(uint256 numTokens) public payable {
        // <yes> <report> ARITHMETIC
        require(msg.value == mul_uint256(numTokens, PRICE_PER_TOKEN));
        // <yes> <report> ARITHMETIC
        balanceOf[msg.sender] = add_uint256(balanceOf[msg.sender], numTokens);
    }

    function sell(uint256 numTokens) public {
        require(balanceOf[msg.sender] >= numTokens);

        balanceOf[msg.sender] = sub_uint256(balanceOf[msg.sender], numTokens);
        // <yes> <report> ARITHMETIC
        msg.sender.transfer(mul_uint256(numTokens, PRICE_PER_TOKEN));
    }
}
