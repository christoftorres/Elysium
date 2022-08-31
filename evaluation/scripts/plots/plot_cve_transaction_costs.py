import matplotlib
import seaborn

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

import numpy as np

#seaborn.set(font_scale=2.1)
seaborn.set(font_scale=1.8)
seaborn.set_style("whitegrid", {'axes.grid' : False})

params = {
  'backend': 'ps',
  'text.usetex': True,
  'font.family': 'serif'
}

def autolabel(rects, ax):
    for rect in rects:
        height = rect.get_height()
        #ax.annotate(r'{:.0f}\%'.format(height),
        ax.annotate(r'{:.0f}%'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height-9.0),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=13)

def autolabel2(rects):
    for rect in rects:
        rect.set_hatch('\\\\\\\\\\\\\\')
        rect.set_color('white')
        rect.set_edgecolor('gray')

#matplotlib.rcParams.update(params)

df = pd.read_json('../../results/CVEs/CVEs-results.json')
print(df)

labels          = ['BEC', 'SMT', 'UET', 'SCA', 'HXG']
#evmpatch_gas    = [df['BEC']['evmpatch']['gas_increase'], df['SMT']['evmpatch']['gas_increase'], df['UET']['evmpatch']['gas_increase'], df['SCA']['evmpatch']['gas_increase'], df['HXG']['evmpatch']['gas_increase']]
evmpatch_gas    = [83,47,237,47,120]
#smartshield_gas = [df['BEC']['smartshield']['gas_increase'], df['SMT']['smartshield']['gas_increase'], df['UET']['smartshield']['gas_increase'], df['SCA']['smartshield']['gas_increase'], df['HXG']['smartshield']['gas_increase']]
smartshield_gas = [80,60,320,0,161]
#elysium_gas     = [df['BEC']['elysium']['gas_increase'], df['SMT']['elysium']['gas_increase'], df['UET']['elysium']['gas_increase'], df['SCA']['elysium']['gas_increase'], df['HXG']['elysium']['gas_increase']]
elysium_gas     = [67,32,195,0,90]

x = np.arange(len(labels))
width = 0.23
space = 0.05

fig, ax = plt.subplots(figsize=(10, 4.8))
rects1 = ax.bar(x - width - space,  evmpatch_gas, width, facecolor='red', edgecolor='gray', alpha=0.25)
rects2 = ax.bar(x,                  smartshield_gas, width, facecolor='limegreen', edgecolor='gray', alpha=0.25)
rects3 = ax.bar(x + width + space,  elysium_gas, width, facecolor='blue', edgecolor='gray', alpha=0.25)

# Axis styling.
#ax.set_ylabel('Deployment Cost Increase (Bytes)')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.tick_params(bottom=False, left=False)
ax.yaxis.grid(False)
ax.xaxis.grid(False)
#ax.yaxis.set_ticklabels([r'0', r'500', r'1,000', r'1,500', r'2,000'])
plt.ylim(0, 400)

# Add legend.
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor='red', edgecolor='gray', alpha=0.25, label=r'\textsc{EVMPatch}'),
    Patch(facecolor='limegreen', edgecolor='gray', alpha=0.25, label=r'\textsc{SmartShield}'),
    Patch(facecolor='blue', edgecolor='gray', alpha=0.25, label=r'\textsc{Elysium}'),
]
#ax.legend(handles=legend_elements, frameon=False, ncol=1, bbox_to_anchor=[0.0, 1.1], loc='upper left')
#ax.legend(handles=legend_elements, frameon=False, ncol=3, bbox_to_anchor=[0.43, 1.3], loc='upper center')
#ax.legend(handles=legend_elements, frameon=False, ncol=3, bbox_to_anchor=[0.43, -0.4], loc='lower center')

# Add annotations.
def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        if height > 0:
            ax.annotate(r'{:.0f}'. format(height),
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom')
autolabel(rects1)
autolabel(rects2)
autolabel(rects3)

plt.tight_layout()

plt.savefig("cve_transaction_costs.pdf", dpi=1000, bbox_inches='tight')
