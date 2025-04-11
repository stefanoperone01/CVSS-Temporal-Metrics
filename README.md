# CVSS-Temporal-Metrics

**CODICE**
Il codice è incorporato all'interno del file main.py.


**OPERAZIONI PRELIMINARI**

**OPENVAS - _DA EFFETTUARE OGNI TANTO_**  
Il file prende in ingresso il file _cve_fixes_ estratto da OpenVAS.
Per estrarre questo file dal database di OpenVAS vanno lanciati i seguenti comandi:
- sudo psql -U postgres -d gvmd (accesso all'utente gvmd di postgres)
- \COPY (SELECT * FROM nvts WHERE nvts.cve IS NOT NULL) TO '/home/kali/Desktop/cve_fixes.csv' WITH CSV HEADER; (salvataggio del database di fix)

A questo punto si lancia il codice _filtering_fixes.py_ per ridurre il peso e filtrare il file _csv_fixes.csv_.

**METASPLOIT** - _DA EFFETTUARE OGNI VOLTA CHE SI VUOLE ESEGUIRE LO SCRIPT_  
Ogni volta che si vuole lanciare lo script bisogna prima aprire la schermata di Metasploit.
Per tale motivo andranno lanciati i seguenti comandi:
- msfconsole
- load msgrpc Pass=mft_password ServerHost=127.0.0.1 ServerPort=55553 SSL=True

A questo punto si può procedere ad eseguire lo script
