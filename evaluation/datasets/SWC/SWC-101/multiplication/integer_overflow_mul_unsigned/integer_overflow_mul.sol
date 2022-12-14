//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

pragma solidity ^0.4.24;

contract IntegerOverflowMul {
    uint256 public count = 2;

    function run(uint256 input) public {
        count *= input;
    }
}
