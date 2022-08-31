contract sGuard{
  function sub_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
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
  
  function add_uint256(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}
/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 54
 */



contract BANK_SAFE
 is sGuard {
    mapping (address=>uint256) public balances;   
   
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
    
     function Deposit() nonReentrant_ 
    public
    payable
    {
        balances[msg.sender] = add_uint256(balances[msg.sender], msg.value);
        Log.AddMessage(msg.sender,msg.value,"Put");
    }
    
     function Collect(uint _am) nonReentrant_ 
    public
    payable
    {
        if(balances[msg.sender]>=MinSum && balances[msg.sender]>=_am)
        {
            // <yes> <report> REENTRANCY
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender] = sub_uint256(balances[msg.sender], _am);
                Log.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }
    
    function() 
    public 
    payable
    {
        Deposit();
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