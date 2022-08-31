//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage

pragma solidity ^0.4.24;

contract IntegerOverflowMinimal {
    int16 public count = 1;

    function run(int16 input) public {
        count -= input;
    }
}
