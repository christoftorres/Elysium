/**
 *Submitted for verification at Etherscan.io on 2020-03-16
*/

pragma solidity 0.8.9;

contract Lock {
    // address owner; slot #0
    // address unlockTime; slot #1
    constructor (address owner, uint256 unlockTime) public payable {
        assembly {
            sstore(0x00, owner)
            sstore(0x01, unlockTime)
        }
    }

    /**
    * @dev        Withdraw function once timestamp has passed unlock time
    */
    fallback() external payable {
        assembly {
          sstore(0x00, add(sload(0x01), 1))
        }
    }
}
