import matplotlib
import seaborn

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

import numpy as np

import glob
import json
import os

#seaborn.set(font_scale=1.7)
#seaborn.set_style("whitegrid", {'axes.grid' : False})

params = {
  'backend': 'ps',
  'text.usetex': True,
  'font.family': 'serif'
}

#matplotlib.rcParams.update(params)

# Analyze execution time
cfg_recovery = list()
pattern = '../../results/Horus/**/*.patched.bin.report.json'
for fname in glob.glob(pattern, recursive=True):
    if os.path.isfile(fname):
        with open(fname, "r") as f:
            report = json.load(f)
            if "%" in report["control_flow_graph_recovery"]:
                cfg_recovery.append(int(report["control_flow_graph_recovery"].replace("%", "")))
            else:
                print("Error: Report does not contain CFG recovery percentage!")
                print(report)
                print(fname)
cfg_recovery = sorted(cfg_recovery)
print(len(cfg_recovery))

cutoff = 90

print("===== Overall CFG Recovery Statistics =====")
print("Max: \t", str(np.max(cfg_recovery))+"%")
print("Mean: \t", str(np.mean(cfg_recovery))+"%")
print("Median: ", str(np.median(cfg_recovery))+"%")
print("Min: \t", str(np.min(cfg_recovery))+"%")
print(str(cutoff)+"%: \t", str(np.percentile(cfg_recovery, cutoff))+"%")
print("===========================================")

plt.plot(cfg_recovery, label="CFG Recovery")
plt.plot([np.percentile(cfg_recovery, cutoff) for _ in cfg_recovery], '--', label=str(cutoff)+"% Cutoff")
plt.ylabel("Percentage Recovered")
plt.legend(loc="lower right")
plt.tight_layout()
plt.savefig("cfg_recovery.pdf", dpi=1000, bbox_inches='tight')
