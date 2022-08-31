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

df = pd.read_json('../../results/SmartBugs/SmartBugs-results.json')
print(df)

#labels           = ['Reentrancy', 'Access Control', 'Integer Overflow', 'Unhandled Exception']
labels           = ['RE', 'AC', 'IO', 'UE']
smartshield_size = [df['reentrancy']['smartshield_size_increase'], df['access_control']['smartshield_size_increase'], df['integer_overflow']['smartshield_size_increase'], df['unhandled_exception']['smartshield_size_increase']]
smartshield_size = [23,0,34,19]
sguard_size      = [df['reentrancy']['sguard_size_increase'], df['access_control']['sguard_size_increase'], df['integer_overflow']['sguard_size_increase'], df['unhandled_exception']['sguard_size_increase']]
sguard_size      = [171,169,112,0]
elysium_size     = [df['reentrancy']['elysium_size_increase'], df['access_control']['elysium_size_increase'], df['integer_overflow']['elysium_size_increase'], df['unhandled_exception']['elysium_size_increase']]
elysium_size     = [27,43,54,12]

x = np.arange(len(labels))
width = 0.23
space = 0.05

fig, ax = plt.subplots(figsize=(8, 5))
rects1 = ax.bar(x - width - space,  smartshield_size, width, facecolor='limegreen', edgecolor='gray', alpha=0.25)
rects2 = ax.bar(x,                  sguard_size, width, facecolor='yellow', edgecolor='gray', alpha=0.25)
rects3 = ax.bar(x + width + space,  elysium_size, width, facecolor='blue', edgecolor='gray', alpha=0.25)

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
plt.ylim(0, 200)

# Add legend.
from matplotlib.patches import Patch
legend_elements = [
    #Patch(facecolor='limegreen', edgecolor='gray', alpha=0.25, label=r'\textsc{SmartShield}'),
    Patch(facecolor='limegreen', edgecolor='gray', alpha=0.25, label=r'SmartShield'),
    #Patch(facecolor='yellow', edgecolor='gray', alpha=0.25, label=r'\textsc{sGuard}'),
    Patch(facecolor='yellow', edgecolor='gray', alpha=0.25, label=r'sGuard'),
    #Patch(facecolor='blue', edgecolor='gray', alpha=0.25, label=r'\textsc{Elysium}'),
    Patch(facecolor='blue', edgecolor='gray', alpha=0.25, label=r'Elysium'),
]
#ax.legend(handles=legend_elements, frameon=False, ncol=3, bbox_to_anchor=[0.45, 1.3], loc='upper center')
#ax.legend(handles=legend_elements, frameon=False, ncol=3, bbox_to_anchor=[0.43, -0.4], loc='lower center')

# Add annotations.
def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        if height > 0:
            ax.annotate(r'{:.0f}'.format(height),
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom')
autolabel(rects1)
autolabel(rects2)
autolabel(rects3)

plt.tight_layout()

plt.savefig("smartbugs_costs.pdf", dpi=1000, bbox_inches='tight')
