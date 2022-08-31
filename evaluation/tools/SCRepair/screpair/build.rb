# Author: Xiao Liang

require 'tempfile'
require 'shellwords'

f = Tempfile.new('err')
IN="{
    \"language\": \"Solidity\",
    \"sources\": {
        \"main\": {
            \"content\": $RC
        }
    },
    \"settings\": {
        \"optimizer\": {
            \"enabled\": true,
        },
        \"outputSelection\": {
            \"*\": {
                '*': [\"evm.deployedBytecode.object\"]
            }
        }
    }
}"

f.close
out = `echo "(jq -n --arg RC #{Shellwords.escape(ENV['R'])} '#{Shellwords.escape(IN)}')" | /bin/solc --standard-json | tee #{Shellwords.escape(f.path)}`

bytecode = `jq -r ".['contracts']['main'][
            #{Shellwords.escape(ENV['C'])}]['evm']['deployedBytecode']['object']" < "#{Shellwords.escape(f.path)}"`

exec("echo #{Shellwords.escape(bytecode)}")
