SCRepair
===

The first automated smart contract gas-optimized vulnerability repair system. SCRepair can automatically generate patches fixing vulnerabilities while attempt to keep the test cases passing. More importantly, SCRepair attempts to generate patches with lower gas usage as long as possible!

Current implementation supports Slither and Oyente as vulnerability detector.
Ethereum smart contract written in Solidity is supported.

Installation
===

To install SCRepair, use the following command, the dependencies will be automatically installed and configured:

```Bash
python3 setup.py install
```


You might need to install the vulnerability detector of choice separately before our repair system can invoke. You may consult the corresponding installation instructions.

To Use
===

Use the following command

```Bash
python3 CLI.py repair PATH_TO_CONTRACT
```

You also need to configure the detectors intended to be used via the `--detector` flag.
Besides, you may use `--targeted_vul` to only target subset of detected vulnerabilities.

As output, the paths to the plausible patches will be printed to the standard out.

Publication
===

Paper "Smart Contract Repair" will appear in TOSEM (ACM Transactions on Software Engineering and Methodology). The full-text is available at https://arxiv.org/abs/1912.05823

If this system is helpful or related to your publication, please cite with the following latex bibtex entry:
```bibtex
@misc{yu2020SCRepair,
    title={Smart Contract Repair},
    author={Xiao Liang Yu and Omar Al-Bataineh and David Lo and Abhik Roychoudhury},
    year={2020},
    journal={ACM Transactions on Software Engineering and Methodology (TOSEM)},
    publisher={ACM New York, NY, USA}
}
```

"Smart Contract Repair" Paper Experiment Dataset
===

Our experiments subjects are the followings:

|Name|Address|
|--|--|
|Autonio	ICO| 0x6994699c731dd7e389c209201ec51e8aff283bf9|
|Airdrop|	0xc7d020d8c92d099b3ade17321310b4815ef20a90|
|BananaCoin|0xd113244b9049943d4bc6fef3048d24edf92dd788|
|XGold Coin|0x83b2fdc4b90706fbee7f4aaafb56356b6dbf25bd|
|Hodbo crowdsale|	0xc8986ecd41fb420268f1f4285931379357c4142b|
|Lescoin presale|	0x87be69e5c196e0309cdf6957fd7141fda1df2b97|
|ClassyCoin|	0x169e59a41ba10600fddd1b0a72921f503b31d96b|
|Yobcoin crowdsale|	0xe07e687dc4b244d574f37490948c7f4aa921d958|
|Classy Coin Airdrop|	0x6459fe2c8d7c26c0011772310d8ca0f570f1d667|
|OKOToken ICO|	0x5027880b5A4C5BBB88D229a334Aa8F31e6e67197|
|ApplauseCash crowdsale|	0xcb58a0bddb9c972d1020d3f9e94c3401960a12d8|
|HDL presale|	0x6a57883b5748bf3631ac2e0d43bf0d6f6cbcd16b|
|Privatix presale|	0x92033cc5d60de8fc01e7d4125713e05194989e1e|
|MXToken crowdsale|	0x0961375ed779fe16435d5d430da00a5bac527e46|
|dgame|	0x0a630de26e5B41eaef08741e74da4018A6C2E14c|
|Easy Mine ICO|	0x53CE47cbe7F2be0AEcD086a70182A98c907D024d|
|Siring Clock Auction|	0x79a198b2355ca2aef695d8a4987582e093911ebb|

The above subjects are either have no balance in the contract at the time we wrote this paper, self-destructed, 
or the detected vulnerabilities reported in our paper cannot be exploited for stealing the Ether stored in the contract.
Please contact us immediately as soon as you find the above described status is no longer up-to-date.

You may access their source code at [etherscan](https://etherscan.io).


People
===

Abhik Roychoudhury, Principal Investigator

Developed by Xiao Liang Yu <xiaoly@comp.nus.edu.sg>
