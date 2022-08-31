import matplotlib
import seaborn

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

import numpy as np

seaborn.set(font_scale=1.7)
seaborn.set_style("whitegrid", {'axes.grid' : False})

params = {
  'backend': 'ps',
  'text.usetex': True,
  'font.family': 'serif'
}

def autolabel(rects, ax):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(r'{:.0f}\%'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height-9.0),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=13)

def autolabel2(rects):
    for rect in rects:
        rect.set_hatch('\\\\\\\\\\\\\\')
        rect.set_color('white')
        rect.set_edgecolor('gray')

matplotlib.rcParams.update(params)

df = pd.read_json('../../results/CVEs/CVEs-results.json')
print(df)

labels              = ['BEC', 'SMT', 'UET', 'SCA', 'HXG']
all                 = [100.0, 100.0, 100.0, 100.0, 100.0]
evmpatch_benign     = [0.0, 0.0, 0.0, df['SCA']['evmpatch']['benign_success']/df['SCA']['benign']*100, df['HXG']['evmpatch']['benign_success']/df['HXG']['benign']*100]
smartshield_benign  = [0.0, 0.0, 0.0, df['SCA']['evmpatch']['benign_success']/df['SCA']['benign']*100, df['HXG']['evmpatch']['benign_success']/df['HXG']['benign']*100]
elysium_benign      = [0.0, 0.0, 0.0, df['SCA']['evmpatch']['benign_success']/df['SCA']['benign']*100, df['HXG']['evmpatch']['benign_success']/df['HXG']['benign']*100]
evmpatch_attacks    = [0.0, 0.0, 0.0, df['SCA']['evmpatch']['attacks_failed']/df['SCA']['attacks']*100, df['HXG']['evmpatch']['attacks_failed']/df['HXG']['attacks']*100]
smartshield_attacks = [0.0, 0.0, 0.0, df['SCA']['evmpatch']['attacks_failed']/df['SCA']['attacks']*100, df['HXG']['evmpatch']['attacks_failed']/df['HXG']['attacks']*100]
elysium_attacks     = [0.0, 0.0, 0.0, df['SCA']['evmpatch']['attacks_failed']/df['SCA']['attacks']*100, df['HXG']['evmpatch']['attacks_failed']/df['HXG']['attacks']*100]

x = np.arange(len(labels))
width = 0.23
space = 0.05

fig, ((ax1), (ax2)) = plt.subplots(2, 1, figsize=(10,9))

rects1 = ax1.bar(x - width - space,  evmpatch_benign, width, facecolor='red', edgecolor='gray', alpha=0.25)
rects2 = ax1.bar(x,                  smartshield_benign, width, facecolor='limegreen', edgecolor='gray', alpha=0.25)
rects3 = ax1.bar(x + width + space,  elysium_benign, width, facecolor='blue', edgecolor='gray', alpha=0.25)
rects4 = ax1.bar(x - width - space,  np.array(all)-np.array(evmpatch_benign), width, bottom=evmpatch_benign, facecolor='white', edgecolor='gray', alpha=0.25)
rects5 = ax1.bar(x,                  np.array(all)-np.array(smartshield_benign), width, bottom=smartshield_benign, facecolor='white', edgecolor='gray', alpha=0.25)
rects6 = ax1.bar(x + width + space,  np.array(all)-np.array(elysium_benign), width, bottom=elysium_benign, facecolor='white', edgecolor='gray', alpha=0.25)

# Add percentage annotations.
autolabel(rects1, ax1)
autolabel(rects2, ax1)
autolabel(rects3, ax1)
autolabel2(rects4)
autolabel2(rects5)
autolabel2(rects6)

rects1 = ax2.bar(x - width - space,  evmpatch_attacks, width, facecolor='red', edgecolor='gray', alpha=0.25)
rects2 = ax2.bar(x,                  smartshield_attacks, width, facecolor='limegreen', edgecolor='gray', alpha=0.25)
rects3 = ax2.bar(x + width + space,  elysium_attacks, width, facecolor='blue', edgecolor='gray', alpha=0.25)
rects4 = ax2.bar(x - width - space,  np.array(all)-np.array(evmpatch_attacks), width, bottom=evmpatch_attacks, facecolor='white', edgecolor='gray', alpha=0.25)
rects5 = ax2.bar(x,                  np.array(all)-np.array(smartshield_attacks), width, bottom=smartshield_attacks, facecolor='white', edgecolor='gray', alpha=0.25)
rects6 = ax2.bar(x + width + space,  np.array(all)-np.array(elysium_attacks), width, bottom=elysium_attacks, facecolor='white', edgecolor='gray', alpha=0.25)

# Add percentage annotations.
autolabel(rects1, ax2)
autolabel(rects2, ax2)
autolabel(rects3, ax2)
autolabel2(rects4)
autolabel2(rects5)
autolabel2(rects6)

# Axis styling.
ax1.set_xticks(x)
ax1.set_title('Successful Benign Transactions')
ax1.set_xticklabels(labels)
ax1.spines['top'].set_visible(False)
ax1.spines['right'].set_visible(False)
ax1.yaxis.set_major_formatter(mtick.PercentFormatter())

ax2.set_xticks(x)
ax2.set_title('Attacks Blocked', pad=15)
ax2.set_xticklabels(labels)
ax2.spines['top'].set_visible(False)
ax2.spines['right'].set_visible(False)
ax2.yaxis.set_major_formatter(mtick.PercentFormatter())

# Add legend.
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor='red', edgecolor='gray', alpha=0.25, label=r'\textsc{EVMPatch}'),
    Patch(facecolor='limegreen', edgecolor='gray', alpha=0.25, label=r'\textsc{SmartShield}'),
    Patch(facecolor='blue', edgecolor='gray', alpha=0.25, label=r'\textsc{Elysium}'),
]
ax1.legend(handles=legend_elements, frameon=False, loc='upper center', ncol=3, bbox_to_anchor=(0.54, 1.35))

plt.tight_layout()

plt.savefig("effectiveness_cves.pdf", dpi=1000, bbox_inches='tight')
