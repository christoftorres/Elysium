# EvmRewriter

## Usage

usage: evm_rewriter.py [-h] -b BYTECODE -m METADATA [-t TIMEOUT] [-o OUTPUT] [-r REPORT] [-d]

An EVM ByteCode Rewriter

optional arguments:
    -h, --help          show this help message and exit
    -b BYTECODE, --bytecode BYTECODE
                        EVM bytecode file (HEX)
    -m METADATA, --metadata METADATA
                        Vulnerability metadata file (JSON)
    -t TIMEOUT, --timeout TIMEOUT
                        Timeout for analyzing and patching in seconds
                        (default to 60 seconds)
    -o OUTPUT, --output OUTPUT
                        Patched EVM bytecode file (HEX)
    -r REPORT, --report REPORT
                        Patching report file (JSON)
    -d, --debug           Debug output

## Test Example
When you are in EvmRewriter directory, type the following code to run a test example.
`python3 evm_rewriter.py -b ./test/Reentrancy.bin -m ./test/metadata.json -r ./test/report.json -o ./test/patchedReentrancy.bin `

## Format of Vulnerability Metadata File

The EvmRewriter tool needs related vulnerability metadata file when it is used to patch a contract.

The format of the metadata file (a json file) is listed below:

```json
{
  "Reentrancy": [
        {
          "callOffset": num,
          "sStoreOffset": num
        },
      {
          "callOffset": num,
          "sStoreOffset": num
      }
  ],
  "IntegerBugs": [
      {
         'offset': num,
         'category': vul_type
      },
      {
         'offset': num,
         'category': vul_type
      }
  ],
  "UnhandledExceptions": [
      {
         "offset": num
      },
      {
         "offset": num
      }
  ]
}
```

**Note:** 

- 1) `callOffset` and `sStoreOffset` represent the position of `call` instruction and `sstore` instruction respectively in the bytecode file. `offset` keyword tells program the vulnerability's position. `category` keyword shows the type of  IntegerBug.
- 2) `num` is a number (e.g. 282) which represents the vulnerability's position in contract, i.e. the vulnerable instruction starts from `num` bytes. 

- 3) `vul_type` is the actual type of IntegerBugs, which only contains the following keywords: `add`, `sub`, `mul`, `div` and `mod`.
- 4) Each item (Reentrancy,  IntegerBugs and UnhandledExceptions) consists of any number of related vulnerability infomation in bytecodes.
- 5) The vulnerability metadata file could be constructed by any other contract detection tools if the results could be reshaped as metioned above.

