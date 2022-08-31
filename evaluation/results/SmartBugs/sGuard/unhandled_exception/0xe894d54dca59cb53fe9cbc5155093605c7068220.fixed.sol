contract sGuard{
  function pow_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    // TODO
    return a ** b;
  }
  
  function mul_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }
}
/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 17
 */


 
contract airDrop is sGuard {
    
    function transfer(address from,address caddress,address[] _tos,uint v, uint _decimals)public returns (bool){
        require(_tos.length > 0);
        bytes4 id=bytes4(keccak256("transferFrom(address,address,uint256)"));
        uint _value = mul_uint256(v, pow_uint256(10, _decimals));
        for(uint i=0;i<_tos.length;i++){
            // <yes> <report> UNCHECKED_LL_CALLS
            caddress.call(id,from,_tos[i],_value);
        }
        return true;
    }
}