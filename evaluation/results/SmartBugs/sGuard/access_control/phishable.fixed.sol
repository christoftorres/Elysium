contract sGuard{
  
}
/*
 * @source: https://github.com/sigp/solidity-security-blog
 * @author: -
 * @vulnerable_at_lines: 20
 */

 

 contract Phishable  is sGuard {
    address public owner;

    constructor (address _owner) {
        owner = _owner;
    }

    function () public payable {} // collect ether

    function withdrawAll(address _recipient) public {
        // <yes> <report> ACCESS_CONTROL
        require(msg.sender == owner);
        _recipient.transfer(this.balance);
    }
}
