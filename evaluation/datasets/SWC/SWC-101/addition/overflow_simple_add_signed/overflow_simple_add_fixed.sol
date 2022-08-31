pragma solidity ^0.4.24;

contract Overflow_Add {
    int120 public balance = -1;

    function add(int120 deposit) public {
        balance = add(balance, deposit);
    }

    function add(int120 a, int120 b) internal pure returns (int120) {
        int120 INT_MAX =  2**(120-1)-1;
        int120 INT_MIN = -2**(120-1);
        if (!((b > 0) && (a > (INT_MAX - b))) && !((b < 0) && (a < (INT_MIN - b)))) {
            return a + b;
        }
        revert();
    }
}
