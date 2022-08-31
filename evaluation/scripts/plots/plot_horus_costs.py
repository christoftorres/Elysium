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

df = pd.read_json('../../results/Horus/Horus-results.json')
print(df)

print(df['unhandled_exception']['smartshield'])

labels           = ['RE', 'AC', 'IO', 'UE']
#smartshield_size = [df['reentrancy']['smartshield']['size_increase'], df['parity_wallet_hack_1']['smartshield']['size_increase'], df['integer_overflow']['smartshield']['size_increase'], df['unhandled_exception']['smartshield']['size_increase']]
smartshield_size = [4,0,32,18]
#elysium_size     = [df['reentrancy']['elysium']['size_increase'], df['parity_wallet_hack_1']['elysium']['size_increase'], df['integer_overflow']['elysium']['size_increase'], df['unhandled_exception']['elysium']['size_increase']]
elysium_size     = [25,36,35,11]

x = np.arange(len(labels))
width = 0.23
space = 0.05

fig, ax = plt.subplots(figsize=(8, 5))
rects1 = ax.bar(x - space - width / 2, smartshield_size, width, facecolor='limegreen', edgecolor='gray', alpha=0.25)
rects3 = ax.bar(x + space + width / 2, elysium_size, width, facecolor='blue', edgecolor='gray', alpha=0.25)

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
#plt.ylim(0, 300)
plt.ylim(0, 40)

# Add legend.
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor='limegreen', edgecolor='gray', alpha=0.25, label=r'\textsc{SmartShield}'),
    Patch(facecolor='yellow', edgecolor='gray', alpha=0.25, label=r'\textsc{sGuard}'),
    Patch(facecolor='blue', edgecolor='gray', alpha=0.25, label=r'\textsc{Elysium}'),
]
#ax.legend(handles=legend_elements, frameon=False, ncol=3, bbox_to_anchor=[0.43, 1.3], loc='upper center')
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
#autolabel(rects2)
autolabel(rects3)

plt.tight_layout()

plt.savefig("horus_costs.pdf", dpi=1000, bbox_inches='tight')
