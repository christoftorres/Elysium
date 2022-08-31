//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

pragma solidity ^0.4.24;

contract IntegerOverflowMul {
    int16 public count = 2;

    function run(int16 input) public {
        count = mul(count, input);
    }

    function mul(int16 a, int16 b) internal pure returns (int16) {
      int16 c = a * b;
      if ((b == 0) || (int16(c / b) == a)) {
          return c;
      }
      revert();
    }
}
