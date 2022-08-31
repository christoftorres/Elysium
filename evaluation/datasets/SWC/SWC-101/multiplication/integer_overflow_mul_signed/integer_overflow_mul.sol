//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

pragma solidity ^0.4.24;

contract IntegerOverflowMul {
    int16 public count = 2;

    function run(int16 input) public {
        count *= input;
    }
}
