//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage
//Safe version

pragma solidity ^0.4.24;

contract IntegerOverflowMul {
    uint256 public count = 2;

    function run(uint256 input) public {
        count = mul(count, input);
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
      uint256 c = a * b;
      if ((b == 0) || (c / b == a)) {
          return c;
      }
      revert();
    }
}
