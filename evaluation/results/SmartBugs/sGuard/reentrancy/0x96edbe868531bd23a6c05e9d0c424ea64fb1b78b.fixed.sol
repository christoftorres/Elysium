contract sGuard{
  function sub_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }
  
  function add_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
  
  bool internal locked_;
  constructor() internal {
    locked_ = false;
  }
  modifier nonReentrant_() {
    require(!locked_);
    locked_ = true;
    _;
    locked_ = false;
  }
}
/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 63
 */



contract PENNY_BY_PENNY  
 is sGuard {
    struct Holder   
    {
        uint unlockTime;
        uint balance;
    }
    
    mapping (address => Holder) public Acc;
    
    uint public MinSum;
    
    LogFile Log;
    
    bool intitalized;
    
     function SetMinSum(uint _val) nonReentrant_ 
    public
    {
        if(intitalized)throw;
        MinSum = _val;
    }
    
     function SetLogFile(address _log) nonReentrant_ 
    public
    {
        if(intitalized)throw;
        Log = LogFile(_log);
    }
    
     function Initialized() nonReentrant_ 
    public
    {
        intitalized = true;
    }
    
     function Put(uint _lockTime) nonReentrant_ 
    public
    payable
    {
        var acc = Acc[msg.sender];
        acc.balance = add_uint256(acc.balance, msg.value);
        if(add_uint256(now, _lockTime)>acc.unlockTime)acc.unlockTime=add_uint256(now, _lockTime);
        Log.AddMessage(msg.sender,msg.value,"Put");
    }
    
     function Collect(uint _am) nonReentrant_ 
    public
    payable
    {
        var acc = Acc[msg.sender];
        if( acc.balance>=MinSum && acc.balance>=_am && now>acc.unlockTime)
        {
            // <yes> <report> REENTRANCY
            if(msg.sender.call.value(_am)())
            {
                acc.balance = sub_uint256(acc.balance, _am);
                Log.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }
    
    function() 
    public 
    payable
    {
        Put(0);
    }
    
}


contract LogFile
 is sGuard {
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }
    
    Message[] public History;
    
    Message LastMsg;
    
    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}