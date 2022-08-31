import matplotlib
import seaborn

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

import numpy as np

import glob
import json
import os

from matplotlib.ticker import FuncFormatter

#seaborn.set(font_scale=2.1)
#seaborn.set_style("whitegrid", {'axes.grid' : False})

params = {
  'backend': 'ps',
  'text.usetex': True,
  'font.family': 'serif'
}

#matplotlib.rcParams.update(params)

# Analyze execution time
execution_times = list()
contract_sizes = list()
execution_times_cfg_recovery = list()
delta_percentage = list()
pattern = '../../results/Horus/**/*.patched.bin.report.json'
for fname in glob.glob(pattern, recursive=True):
    if os.path.isfile(fname):
        with open(fname, "r") as f:
            report = json.load(f)
            if "execution_time" in report and "control_flow_graph_recovery_time" in report:
                execution_times.append(report["execution_time"])
                execution_times_cfg_recovery.append(report["control_flow_graph_recovery_time"])
                delta_percentage.append(report["control_flow_graph_recovery_time"] / report["execution_time"])
                bname = fname.replace("results", "datasets").replace("elysium", "contracts").replace(".patched.bin.report.json", ".bin")
                with open(bname, "r") as b:
                    bytecode = b.read()
                    bsize = len(bytecode) / 2
                    contract_sizes.append(bsize)
execution_times = sorted(execution_times)
contract_sizes = sorted(contract_sizes)
assert(len(execution_times) == len(contract_sizes))
execution_times_cfg_recovery = sorted(execution_times_cfg_recovery)

cutoff = 90

print("Smart Contracts: ", len(execution_times))

print("===== Overall Execution Time Statistics =====")
print("Max: \t", np.max(execution_times), "seconds")
print("Mean: \t", np.mean(execution_times), "seconds")
print("Median: ", np.median(execution_times), "seconds")
print("Min: \t", np.min(execution_times), "seconds")
print(str(cutoff)+"%: \t", np.percentile(execution_times, cutoff), "seconds")
print("=============================================")

print("===== CFG Recovery Execution Time Statistics =====")
print("Max: \t", np.max(execution_times_cfg_recovery), "seconds")
print("Mean: \t", np.mean(execution_times_cfg_recovery), "seconds")
print("Median: ", np.median(execution_times_cfg_recovery), "seconds")
print("Min: \t", np.min(execution_times_cfg_recovery), "seconds")
print(str(cutoff)+"%: \t", np.percentile(execution_times_cfg_recovery, cutoff), "seconds")
print("==================================================")

print("Average percentage of CFG recovery time of overall execution time:", np.mean(delta_percentage) * 100)

def human_format(num, pos):
    magnitude = 0
    while abs(num) >= 1000:
        magnitude += 1
        num /= 1000.0
    # add more suffixes if you need them
    return '%.0f%s' % (num, ['', 'KB', 'MB', 'GB', 'TB', 'PB'][magnitude])

formatter = FuncFormatter(human_format)

fig, ax = plt.subplots(figsize=(5, 2.5))

l1, = ax.plot(execution_times)
ax.set_ylabel("Seconds")
ax.set_yscale('log')
ax2 = ax.twinx()
l2, = ax2.plot(contract_sizes, color="red")
ax2.yaxis.set_major_formatter(formatter)
l3, = ax.plot([np.percentile(execution_times, cutoff) for _ in execution_times], '--')
ax.annotate(str(cutoff)+"% Cutoff", (0, 2))
ax.legend([l1, l2], ["Execution Time", "Contract Size"], loc="upper left", frameon=False, ncol=1)

plt.tight_layout()
plt.savefig("execution_time.pdf", dpi=1000, bbox_inches='tight')
