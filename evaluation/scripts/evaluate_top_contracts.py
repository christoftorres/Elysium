
import os
import re
import json
import shlex
import subprocess
import numpy as np

from subprocess import STDOUT, check_output

def measure_losc(source_code):
    source_code = re.sub(re.compile("/\*.*?\*/", re.DOTALL), "", source_code)
    source_code = re.sub(re.compile("//.*?\n" ), "", source_code)
    return len([line for line in source_code.splitlines() if line.strip() != ''])

def measure_functions(source_code):
    return len([line for line in source_code.splitlines() if line.replace(" ", "").replace("\t", "").startswith("function") or line.replace(" ", "").replace("\t", "").startswith("fallback")])

def main():
    with open("top_contracts.json", "r") as f:
        contracts = json.load(f)
        print("Number of contracts:", len(contracts))

        if not os.path.exists("top_contracts"):
            os.mkdir("top_contracts")

        cfg_percentages_original, cfg_build_times_original = list(), list()
        cfg_percentages_elysium, cfg_build_times_elysium = list(), list()
        losc, functions = list(), list()
        if os.path.exists("top_contracts_results.csv"):
            with open("top_contracts_results.csv", "r") as f:
                lines = f.readlines()
                for line in lines[1:]:
                    line = line.split(",")
                    print(line)
                    for contract in contracts:
                        if contract["Address"] == line[0]:
                            losc.append(measure_losc(contract["SourceCode"]))
                            functions.append(measure_functions(contract["SourceCode"]))
                    cfg_percentages_original.append(float(line[3]))
                    cfg_build_times_original.append(float(line[4]))
                    cfg_percentages_elysium.append(float(line[5]))
                    cfg_build_times_elysium.append(float(line[6]))


        else:
            with open("top_contracts_results.csv", "w") as f:
                f.write("Contract Address,LoSC,Functions,CFG Percentage (Original),CFG Build Time (Original),CFG Percentage (Elysium),CFG Build Time (Elysium),Free Storage Location (Elysium),Free Storage Location (solc)\n")
                for contract in contracts:
                    print(contract["Address"], "\t", contract["CompilerVersion"], "\t", contract["Percentage"], "\t", round(contract["Balance"]), "\t", contract["ContractName"])
                    with open("top_contracts/"+contract["Address"]+".sol", "w") as g:
                        g.write(contract["SourceCode"])

                    compiler_version = contract["CompilerVersion"].split("-")[0].split("+")[0].replace("v", "")
                    p = subprocess.Popen(shlex.split('solc-select install '+compiler_version), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    p.communicate()[0].decode("utf-8")
                    p = subprocess.Popen(shlex.split('solc-select use '+compiler_version), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    p.communicate()[0].decode("utf-8")

                    print('python3 ../elysium/elysium.py -s top_contracts/'+contract["Address"]+'.sol -c '+contract["ContractName"]+' -i')
                    try:
                        out = check_output(shlex.split('python3 ../elysium/elysium.py -s top_contracts/'+contract["Address"]+'.sol -c '+contract["ContractName"]+' -i'), stderr=STDOUT, timeout=30*60).decode("utf-8")
                    except Exception as e:
                        print(e)
                        if "timed out" in str(e):
                            out = "Timeout"
                        else:
                            print(out)
                            out = ""
                        pass

                    if out != "Timeout":
                        try:
                            cfg_percentage_original = float(re.compile("\[Original\] Recovered (.+?)% of the control-flow graph").findall(out)[0])
                            cfg_percentages_original.append(cfg_percentage_original)
                            cfg_build_time_original = float(re.compile("in (.+?) second\(s\). \[Original\]").findall(out)[0])
                            cfg_build_times_original.append(cfg_build_time_original)
                            cfg_percentage_elysium = float(re.compile("\[Elysium\] Recovered (.+?)% of the control-flow graph").findall(out)[0])
                            cfg_percentages_elysium.append(cfg_percentage_elysium)
                            cfg_build_time_elysium = float(re.compile("in (.+?) second\(s\). \[Elysium\]").findall(out)[0])
                            cfg_build_times_elysium.append(cfg_build_time_elysium)
                        except:
                            cfg_percentage_original = ""
                            cfg_build_time_original = ""
                            cfg_percentage_elysium = ""
                            cfg_build_time_elysium = ""
                    else:
                        cfg_percentage_original = out
                        cfg_build_time_original = out
                        cfg_percentage_elysium = out
                        cfg_build_time_elysium = out
                    if out != "Timeout":
                        try:
                            free_storage_location = int(re.compile("Free storage location detected: ([0-9]+)").findall(out)[0])
                            free_storage_location_solc = int(re.compile("Free storage location detected from storage layout: ([0-9]+)").findall(out)[0])
                        except:
                            free_storage_location = ""
                            free_storage_location_solc = ""
                    else:
                        free_storage_location = out
                        free_storage_location_solc = out

                    f.write(contract["Address"]+","+str(measure_losc(contract["SourceCode"]))+","+str(measure_functions(contract["SourceCode"]))+","+str(cfg_percentage_original)+","+str(cfg_build_time_original)+","+str(cfg_percentage_elysium)+","+str(cfg_build_time_elysium)+","+str(free_storage_location)+","+str(free_storage_location_solc)+","+str(free_storage_location == free_storage_location_solc)+"\n")

        print("min cfg_percentage_original:", np.min(cfg_percentages_original))
        print("max cfg_percentage_original:", np.max(cfg_percentages_original))
        print("mean cfg_percentage_original:", np.mean(cfg_percentages_original))
        print("median cfg_percentage_original:", np.median(cfg_percentages_original))
        print()
        print("min cfg_build_time_original:", np.min(cfg_build_times_original))
        print("max cfg_build_time_original:", np.max(cfg_build_times_original))
        print("mean cfg_build_time_original:", np.mean(cfg_build_times_original))
        print("median cfg_build_time_original:", np.median(cfg_build_times_original))
        print()
        print("min cfg_percentage_elysium:", np.min(cfg_percentages_elysium))
        print("max cfg_percentage_elysium:", np.max(cfg_percentages_elysium))
        print("mean cfg_percentage_elysium:", np.mean(cfg_percentages_elysium))
        print("median cfg_percentage_elysium:", np.median(cfg_percentages_elysium))
        print()
        print("min cfg_build_time_elysium:", np.min(cfg_build_times_elysium))
        print("max cfg_build_time_elysium:", np.max(cfg_build_times_elysium))
        print("mean cfg_build_time_elysium:", np.mean(cfg_build_times_elysium))
        print("median cfg_build_time_elysium:", np.median(cfg_build_times_elysium))
        print()
        print("cfg_percentage_original fully recovered", len([i for i in cfg_percentages_original if i == 100.0]))
        print("cfg_percentages_elysium fully recovered", len([i for i in cfg_percentages_elysium if i == 100.0]))
        print()
        print("min improvement:", np.min([cfg_percentages_elysium[i] - cfg_percentages_original[i] for i in range(len(cfg_percentages_original)) if cfg_percentages_original[i] != 100.0 and cfg_percentages_elysium[i] - cfg_percentages_original[i] > 0]))
        print("max improvement:", np.max([cfg_percentages_elysium[i] - cfg_percentages_original[i] for i in range(len(cfg_percentages_original)) if cfg_percentages_original[i] != 100.0 and cfg_percentages_elysium[i] - cfg_percentages_original[i] > 0]))
        print("mean improvement:", np.mean([cfg_percentages_elysium[i] - cfg_percentages_original[i] for i in range(len(cfg_percentages_original)) if cfg_percentages_original[i] != 100.0 and cfg_percentages_elysium[i] - cfg_percentages_original[i] > 0]))
        print("median improvement:", np.median([cfg_percentages_elysium[i] - cfg_percentages_original[i] for i in range(len(cfg_percentages_original)) if cfg_percentages_original[i] != 100.0 and cfg_percentages_elysium[i] - cfg_percentages_original[i] > 0]))
        print()
        print("min losc:", np.min(losc))
        print("max losc:", np.max(losc))
        print("mean losc:", np.mean(losc))
        print("median losc:", np.median(losc))
        print()
        print("min functions:", np.min(functions))
        print("max functions:", np.max(functions))
        print("mean functions:", np.mean(functions))
        print("median functions:", np.median(functions))
        print()


if __name__ == "__main__":
    main()
