import pandas as pd

# Percorso del file di input e di output
input_csv = r"C:\Users\stefa\Desktop\cve_fixes.csv"  # Sostituisci con il nome del tuo file CSV
output_csv = r"C:\Users\stefa\Desktop\cve_fixes_filtered.csv"

# Leggere il file CSV
df = pd.read_csv(input_csv)
print(len(df))
# Selezionare solo le colonne richieste
colonne_da_mantenere = [
    "name", "summary", "impact", "cve", "cvss_base", "solution", "solution_type", "detection"
]

# Creare un nuovo dataframe con le colonne selezionate
df_filtrato = df[colonne_da_mantenere]
print(len(df_filtrato))
df_filtrato = df_filtrato.dropna(subset=['cve'])
# Salvare il nuovo CSV
df_filtrato.to_csv(output_csv, index=False)

print(f"File CSV filtrato salvato come: {output_csv}")
