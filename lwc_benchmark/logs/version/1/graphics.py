import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import io
from datetime import datetime

# 0. Egyedi időbélyeg generálása (ÉÉÉÉMMDD_HHMMSS formátumban)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# 1. Bemeneti CSV fájl beolvasása és tisztítása
with open('meresek-03.csv', 'r', encoding='utf-8') as f:
    lines = f.readlines()

csv_lines = []
recording = False
for line in lines:
    if 'Algoritmus,Muvelet,Meret,Ciklus' in line:
        recording = True
    if recording:
        if line.startswith('---') or line.startswith('Meres befejezve'):
            break
        csv_lines.append(line)

df = pd.read_csv(io.StringIO("".join(csv_lines)))

# 2. Adattípusok és Származtatott Metrikák Számítása
df['Meret'] = df['Meret'].astype(int)
df['Ciklus'] = df['Ciklus'].astype(float)

# A) Futási idő milliszekundumban (80 MHz-es STM32 órajel mellett: 1 ms = 80 000 ciklus)
df['Ido_ms'] = df['Ciklus'] / 80000.0

# B) CPB (Cycles Per Byte / Ciklus / Bájt): Ciklusszám osztva a csomagmérettel
df['CPB'] = df.apply(lambda row: row['Ciklus'] / row['Meret'] if row['Meret'] > 0 else 0, axis=1)

# C) Átviteli sebesség kB/s-ban (Throughput): (Bájt * 80 000) / Ciklusszám
df['Throughput_kBps'] = df.apply(lambda row: (row['Meret'] * 80000.0) / row['Ciklus'] if row['Ciklus'] > 0 else 0, axis=1)

sns.set_theme(style="whitegrid")

# =========================================================
# 1. GRAFIKON: Skálázódás a csomagméret függvényében (Titkosítás)
# =========================================================
plt.figure(figsize=(10, 6), dpi=300)
df_enc = df[(df['Muvelet'] == 'Encrypt') & (df['Meret'] > 0)]

sns.lineplot(
    data=df_enc,
    x='Meret',
    y='Ido_ms',
    hue='Algoritmus',
    marker='o',
    linewidth=2.5,
    markersize=8
)
plt.xscale('log', base=2)
plt.yscale('log')
plt.xticks([16, 64, 256, 1024], ['16 B', '64 B', '256 B', '1024 B'])
plt.title('Titkosítási idő skálázódása a csomagméret függvényében (80 MHz)', fontsize=12, fontweight='bold')
plt.xlabel('Csomagméret (Bájt)', fontsize=11)
plt.ylabel('Futási idő (ms - log skála)', fontsize=11)
plt.grid(True, which="both", ls="--", alpha=0.5)
plt.tight_layout()

file1 = f'1_skalazodas_csomagmeret_{timestamp}.png'
plt.savefig(file1, dpi=300)
plt.close()

# =========================================================
# 2. GRAFIKON: CPB (Cycles Per Byte / Fajlagos költség @ 1024 B)
# =========================================================
plt.figure(figsize=(10, 6), dpi=300)
df_1024 = df[(df['Meret'] == 1024) & (df['Muvelet'] != 'KeyGen')].copy()

ax2 = sns.barplot(
    data=df_1024,
    x='Algoritmus',
    y='CPB',
    hue='Muvelet',
    palette='Set2'
)
plt.yscale('log')
plt.title('Fajlagos erőforrás-igény: CPB (Ciklus / Bájt) @ 1024 Bájt', fontsize=12, fontweight='bold')
plt.xlabel('Algoritmus / Üzemmód', fontsize=11)
plt.ylabel('CPB (Ciklus/Bájt - log skála)', fontsize=11)
plt.grid(True, which="both", ls="--", alpha=0.5)

for p in ax2.patches:
    height = p.get_height()
    if height > 0:
        ax2.annotate(f'{height:.1f}',
                    (p.get_x() + p.get_width() / 2., height),
                    ha='center', va='bottom',
                    fontsize=8, xytext=(0, 3),
                    textcoords='offset points')

plt.tight_layout()

file2 = f'2_cpb_osszehasonlitas_{timestamp}.png'
plt.savefig(file2, dpi=300)
plt.close()

# =========================================================
# 3. GRAFIKON: Átviteli sebesség (Throughput in kB/s @ 1024 B)
# =========================================================
plt.figure(figsize=(10, 6), dpi=300)

ax3 = sns.barplot(
    data=df_1024,
    x='Algoritmus',
    y='Throughput_kBps',
    hue='Muvelet',
    palette='viridis'
)
plt.title('Átviteli sebesség (Throughput) 1024 B csomagnál (STM32L432KC @ 80 MHz)', fontsize=12, fontweight='bold')
plt.xlabel('Algoritmus / Üzemmód', fontsize=11)
plt.ylabel('Átviteli sebesség (kB/s)', fontsize=11)
plt.grid(True, which="both", ls="--", alpha=0.5)

for p in ax3.patches:
    height = p.get_height()
    if height > 0:
        ax3.annotate(f'{height:.0f} kB/s',
                    (p.get_x() + p.get_width() / 2., height),
                    ha='center', va='bottom',
                    fontsize=8, xytext=(0, 3),
                    textcoords='offset points')

plt.tight_layout()

file3 = f'3_atviteli_sebesseg_{timestamp}.png'
plt.savefig(file3, dpi=300)
plt.close()

# =========================================================
# 4. GRAFIKON: Kulcsgenerálás / Előkészítés (KeyGen)
# =========================================================
plt.figure(figsize=(8, 5), dpi=300)
df_keygen = df[df['Muvelet'] == 'KeyGen']

ax4 = sns.barplot(
    data=df_keygen,
    x='Algoritmus',
    y='Ciklus',
    hue='Algoritmus',
    palette='magma',
    legend=False
)
plt.title('Kulcsgenerálás / Kulcskiterjesztés ciklusszáma (KeyGen)', fontsize=12, fontweight='bold')
plt.xlabel('Algoritmus', fontsize=11)
plt.ylabel('Órajelciklusok száma', fontsize=11)
plt.grid(True, which="both", ls="--", alpha=0.5)

for p in ax4.patches:
    height = p.get_height()
    ax4.annotate(f'{int(height)}',
                (p.get_x() + p.get_width() / 2., height),
                ha='center', va='bottom',
                fontsize=9, xytext=(0, 3),
                textcoords='offset points')

plt.tight_layout()

file4 = f'4_keygen_ciklusok_{timestamp}.png'
plt.savefig(file4, dpi=300)
plt.close()

print(f"Minden grafikon sikeresen elkészült (Időbélyeg: {timestamp}):")
print(f" - {file1}")
print(f" - {file2}")
print(f" - {file3}")
print(f" - {file4}")