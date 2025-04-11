# CVSS-Temporal-Metrics

Il codice è incorporato all'interno del file main.py.

Il file prende in ingresso il file cve_fixes estratto da OpenVAS.
Per estrarre questo file dal database di OpenVAS vanno lanciati i seguenti comandi:
- sudo psql -U postgres -d gvmd (accesso all'utente gvmd di postgres)
- \COPY (SELECT * FROM nvts WHERE nvts.cve IS NOT NULL) TO '/home/kali/Desktop/cve_fixes.csv' WITH CSV HEADER; (salvataggio del database di fix)
- 
