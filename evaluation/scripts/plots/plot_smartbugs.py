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

matplotlib.rcParams.update(params)

df = pd.read_json('../../results/SmartBugs/SmartBugs-results.json')
print(df)

labels      = ['Reentrancy', 'Access Control', 'Integer Overflow', 'Unhandled Exception']
all         = [100.0, 100.0, 100.0, 100.0]
smartshield = np.array([df['reentrancy']['smartshield_patched_vulnerabilities']/df['reentrancy']['validated_vulnerabilities']*100, df['access_control']['smartshield_patched_vulnerabilities']/df['access_control']['validated_vulnerabilities']*100, df['integer_overflow']['smartshield_patched_vulnerabilities']/df['integer_overflow']['validated_vulnerabilities']*100, df['unhandled_exception']['smartshield_patched_vulnerabilities']/df['unhandled_exception']['validated_vulnerabilities']*100])
sguard      = [df['reentrancy']['sguard_patched_vulnerabilities']/df['reentrancy']['validated_vulnerabilities']*100, df['access_control']['sguard_patched_vulnerabilities']/df['access_control']['validated_vulnerabilities']*100, df['integer_overflow']['sguard_patched_vulnerabilities']/df['integer_overflow']['validated_vulnerabilities']*100, df['unhandled_exception']['sguard_patched_vulnerabilities']/df['unhandled_exception']['validated_vulnerabilities']*100]
elysium     = [df['reentrancy']['elysium_patched_vulnerabilities']/df['reentrancy']['validated_vulnerabilities']*100, df['access_control']['elysium_patched_vulnerabilities']/df['access_control']['validated_vulnerabilities']*100, df['integer_overflow']['elysium_patched_vulnerabilities']/df['integer_overflow']['validated_vulnerabilities']*100, df['unhandled_exception']['elysium_patched_vulnerabilities']/df['unhandled_exception']['validated_vulnerabilities']*100]

x = np.arange(len(labels))
width = 0.225
space = 0.05

fig, ax = plt.subplots(figsize=(10,5))
rects1 = ax.bar(x - width - space,  smartshield, width, facecolor='limegreen', edgecolor='gray', alpha=0.25)
rects2 = ax.bar(x,                  sguard, width, facecolor='yellow', edgecolor='gray', alpha=0.25)
rects3 = ax.bar(x + width + space,  elysium, width, facecolor='blue', edgecolor='gray', alpha=0.25)

rects4 = ax.bar(x - width - space,  np.array(all)-np.array(smartshield), width, bottom=smartshield, facecolor='white', edgecolor='gray', alpha=0.25)
rects5 = ax.bar(x,                  np.array(all)-np.array(sguard), width, bottom=sguard, facecolor='white', edgecolor='gray', alpha=0.25)
rects6 = ax.bar(x + width + space,  np.array(all)-np.array(elysium), width, bottom=elysium, facecolor='white', edgecolor='gray', alpha=0.25)

# Axis styling.
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.tick_params(bottom=False, left=False)
ax.yaxis.grid(False)
ax.xaxis.grid(False)
ax.spines['left'].set_bounds(0, 100)
ax.yaxis.set_ticklabels([r'0\%', r'20\%', r'40\%', r'60\%', r'80\%', r'100\%'])
plt.ylim(0, 125)

# Add legend.
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor='limegreen', edgecolor='gray', alpha=0.25, label=r'\textsc{SmartShield}'),
    Patch(facecolor='yellow', edgecolor='gray', alpha=0.25, label=r'\textsc{sGuard}'),
    Patch(facecolor='blue', edgecolor='gray', alpha=0.25, label=r'\textsc{Elysium}'),
]
ax.legend(handles=legend_elements, frameon=False, loc='upper center', ncol=3)

# Add percentage annotations.
def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(r'{:.0f}\%'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height-9.0),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=15)

def autolabel2(rects):
    for rect in rects:
        rect.set_hatch('\\\\\\\\\\\\\\')
        rect.set_color('white')
        rect.set_edgecolor('gray')

autolabel(rects1)
autolabel(rects2)
autolabel(rects3)

autolabel2(rects4)
autolabel2(rects5)
autolabel2(rects6)

fig.tight_layout()

plt.savefig("effectiveness_smartbugs.pdf", dpi=1000, bbox_inches='tight')
