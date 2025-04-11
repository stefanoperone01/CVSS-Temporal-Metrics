import csv
import requests
from io import StringIO
from pymetasploit3.msfrpc import MsfRpcClient
from pymetasploit3.msfrpc import MsfModule
import pandas as pd
import json

# Funzione per ottenere i dati CVE dalla NVD
def get_cve_data(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"  # URL
    headers = {
        'apiKey': '89e8dbc9-8b0d-47bf-a359-1812279ff8c1'  # Chiave API
    }

    # Richiesta all'API
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Errore nel recupero dei dati: {response.status_code}")
        return None


def extract_cvss_base_score(cve_json):
    """
    Estrae il CVSS base score dal JSON dei dati CVE.

    :param cve_json: Il JSON restituito dall'API NVD per un CVE.
    :return: Il CVSS base score o un messaggio se non trovato.
    """
    if not cve_json:
        return "Nessun dato fornito."

    try:
        # Naviga nei dati JSON
        vulnerabilities = cve_json.get("vulnerabilities", [])
        if not vulnerabilities:
            return "Nessuna vulnerabilità trovata."

        # Estrai la sezione 'metrics'
        metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})

        # Prova a estrarre CVSS v3.1
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        # Prova CVSS v3.0
        elif "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        # Prova CVSS v2
        elif "cvssMetricV2" in metrics:
            return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        else:
            return "Nessun punteggio CVSS trovato."

    except (KeyError, IndexError, TypeError) as e:
        return f"Errore nell'estrazione del CVSS: {e}"


def search_metasploit_exploits(cve_input):
    """Recupera gli exploit associati alla CVE da Metasploit e le relative piattaforme."""
    print("Ricerca su Metasploit...")
    try:
        # Connessione al client Metasploit
        client = MsfRpcClient("mft_password", server="127.0.0.1", port=55553, ssl=True)
        # Cerca i moduli exploit associati alla CVE specificata
        modules = client.modules.search(f"type:exploit cve:{cve_input}")

        # Prepara la lista di risultati
        exploit_details = []
        rankings_values = {"excellent": 5, "great": 5, "good": 4, "normal": 4}
        rankings = []

        for module in modules:
            # Ottieni il nome del modulo exploit
            rank = module['rank']
            # verifica se rank è una chiave del dizionario rankings_values e se è presente estrai il valore
            if rank in rankings_values.keys():
                rankings.append(rankings_values[rank])
            else:
                rankings.append(3)
            exploit_details.append({
                "name": module['fullname'],
                "description": module.get('description', 'N/A'),
                "rank": module.get('rank', 'unknown'),
            })
        if exploit_details != []:
            if rankings != []:
                rank = max(rankings)
            else:
                rank = 3
        else:
            rank = 2

        return exploit_details, rank

    except Exception as e:
        print(f"[!] Errore durante la ricerca dei moduli da Metasploit: {e}")
        return []


# Funzione per cercare exploit in Exploit-DB
def search_exploitdb_online(cve_id):
    """
    Cerca una CVE direttamente nel file CSV di Exploit-DB online.
    :param cve_id: Identificativo CVE (es. CVE-2022-1234)
    :return: Lista di exploit trovati
    """

    # URL del file CSV di Exploit-DB
    csv_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    exploits = []
    try:
        print(f"Accesso al file CSV online da {csv_url}...")
        response = requests.get(csv_url)
        if response.status_code == 200:
            # Converte il contenuto in una struttura leggibile come file
            csv_content = StringIO(response.text)
            reader = csv.DictReader(csv_content)

            for row in reader:
                if cve_id in row.get("codes", "") or cve_id in row.get("description", ""):
                    exploit = {
                        "id": row['id'],
                        "description": row['description'],
                        "date_published": row['date_published'],
                        "author": row['author'],
                        "type": row['type'],
                        "platform": row['platform'],
                        "url": f"https://www.exploit-db.com/exploits/{row['id']}",
                        "verified": row['verified']
                    }
                    exploits.append(exploit)
            return exploits
        else:
            print(f"Errore durante l'accesso al file CSV online: {response.status_code}")
            return []
    except Exception as e:
        print(f"Errore durante l'accesso al file CSV online: {e}")
        return []


def exploitdb_values(exploits):
    values = []
    for exploit in exploits:
        values.append(exploit['verified'])
    if 1 in values:
        return 4
    else:
        return 3


# Funzione per cercare exploit su PacketStorm
def search_packetstorm_exploits(cve_id):
    url = "https://api.packetstormsecurity.com/v31337.20240702/dev-api"
    api_secret = "81d5c066-0352-4031-a827-7c1b777834c0|97fba7a0f1882d418c48b5eee2aae627f904e2fa311b07a73677bdf1dda6d85fba04475dc28ec433692d703e05c33b02248e00600a98cb24decd0837087373c959fc911e67277c3a893ce5c6566cee3512fd6395a66f87bf46332d7caee6c2684de0d95d45f9249c0829fa59caf260a7f6b255cb6d05491cd78d02cf919b26579e63c43d4e5e9b9c89d9e9af835acd006ab02a1b5cf864a40426df3954cf951910c16dc17b882181e7fcad1588dc3ac23b080e6eb004823fc9efe773cb0dec9ab7253067dc0e41fb76ef6a49f2f0795bf5ad1f163d826e3340f44b85f4ed69c8ee05ef555471865f1447d523d14e4796d045738defef638f5f6d1df196d1d83cd18265864b358b7b5c8eefc87f32f7b7e13396f7e4b2d5cbf3cebad80c4ae97feb079a507e6019b13444d5e285da008417b75d9300f902b2b692d4be0997c5c712271ce779d4297700330f2bf6c52a7e2b927eac84f0d3e6ad24a3f80be21cff05da7a27e6b44b0fbf313a865b531973d0bf833404d7252172d4c324360f3bb336db9f40414465e5a6a3fa20750b0837298b34b4166f4ec7193fe1015a0672afaf02b78ba7ddc256629be01bf9480a3a4840216c0f1ba3d15b35eafa2e0dbb2967896b7cfcb4264408ef0260b667f2ab46441c8a6a4a96d411a812568f75ffc59e07dccddac0a9394e325753dd0e3dff2ed5209e83bf04f6247a2bf934000749f2efdf5174f9908e9abb64a346d788a8d86d0d0c921981db8a596f865d4c137aa807c95040e6bdbe84fc5ba9ebff06579dea20d5f8a1b0f150659b98930b07e01c2543d3b678a154347c828202fcac7e384f371649ffee6f25539258bb5d7f66d079be3a17974762df3ecbce2e63c3927208a1225a5d577d592f206f74bbcd5126fa73ee0da75eaafb99f2f81eebb360c81e5a88cc2b91e5bf470ee3a33c16ca2e339c18616af03e23ccd7c1e4f7974e5dd1e72f83f71b2f0fd08d06771b89434aa6df4c0e073ddcc7097347b09f8edb49faf5667a8bc8968f20dba38ffe9d9af7fa96db760733f283cf3acbfd692e89267e6334cceda138c94b9754d38197d19d845633f47ee9982518a7f6b33728e344b7590f93240e0320a3578fcbc6cd6371c2448e120678bd157a9aa1fe4fa18df5f75f836f1ba4df4b055792590bc81cce06132a0f84133efcab9d5834e5ca8ff1d233031ebf6b4cbbd498e1f91c24064c9fba99a36914445c2418634a2cdcd7eea4d4a36f947c5fd1ccc26cc445d93a88bf95331f09d680412a8022c01daa1c98cab955aefd1f693c1047c14182300997be80f5ed1fa0416581688e582f60234c02b0bc903e68e95d8a8e318e45eb415ec20f50c3c3ffb2cff48f70efe974298c7837a2fef06b1c773244d7536ad4b3242dee8c51cf5deb2b2d765bffb2755ed2e8390f0ebedf1c72f01d0d45846a02"
    ### L'API SCADE A INIZIO APRILE, OGNI MESE SI RINNOVA ###
    headers = {"apisecret": api_secret}
    body = f'area=files&section=cve&id={cve_id}&page=1'

    # Effettua la richiesta POST
    response = requests.post(url, data=body, headers=headers)
    if response.status_code == 200:
        try:
            # Converte la risposta in un dizionario JSON
            response_json = json.loads(response.text)

            # Naviga fino alla sezione "files"
            files = response_json.get("files", {})
            exploits = []
            for file_key, file_data in files.items():
                # Naviga nei metadati
                meta = file_data.get("meta", {})
                tags = meta.get("tags", {})

                for tag_key, tag_data in tags.items():
                    # Verifica se il nome del tag è "Exploit"
                    if tag_data.get("name") == "Exploit":
                        # print(f'Tag "Exploit" trovato in {tag_key}')
                        exploits.append(file_data)
            return exploits

        except json.JSONDecodeError:
            print("Errore nel parsing del JSON.")
            return None

    else:
        print(f"Errore nella richiesta API. Codice HTTP: {response.status_code}")
        return None


# Funzione per determinare la valutazione finale
def evaluate_exploit(rank):
    """Determina la valutazione finale dell'exploit basata sull'Exploitability Score e altri fattori."""
    score = {2: "Unproven (U)", 3: "Proof-of-Concept (P)", 4: "Functional (F)", 5: "High (H)"}
    return score[rank]


def remediation(cve_id):
    # apri il file estratto da OpenVAS e leggi il contenuto su un dataframe
    df = pd.read_csv('/home/kali/Desktop/cve_fixes_filtered.csv')

    # salve le righe del dataframe in cui la cve è presente su un file csv
    df2 = df[df['cve'].str.contains(cve_id)]

    # crea un dizionario chiave-valore con chiavi: 'NoneAvailable', 'WillNotFix', 'Workaround', 'Mitigation', 'VendorFix' e valori:
    # Not Defined (X), Unavailable (U), Workaround (W), Temporary Fix (T), Official Fix (O)

    dict = {'NoneAvailable': 0, 'WillNotFix': 1, 'Workaround': 2, 'Mitigation': 3, 'VendorFix': 4}

    dict2 = {0: 'Unavailable (U)', 1: 'Unavailable (U)', 2: 'Temporary Fix (T)', 3: 'Workaround (W)', 4: 'Official Fix (O)'}

    index = 0

    # verifica il valore del campo 'solution_type' per ogni riga del dataframe
    for i in df2['solution_type']:
        # se il valore è una chiave del dizionario, seleziona il valore corrispondente
        if i in dict:
            if dict[i] > index:
                index = dict[i]

    # stampa il valore di dict2 corrispondente all'indice
    return dict2[index]


# Funzione principale
def compute_cvss_score(cvss_score, ecm_value, fix_value, confidence_value):
    dict_ecm = {'Not Defined (X)': 1, 'Unproven (U)': 0.91, 'Proof-of-Concept (P)': 0.94, 'Functional (F)': 0.97,
                'High (H)': 1}
    dict_fix = {'Not Defined (X)': 1, 'Unavailable (U)': 1, 'Workaround (W)': 0.97, 'Temporary Fix (T)': 0.96,
                'Official Fix (O)': 0.95}
    dict_conf = {'Not Defined (X)': 1, 'Unknown (U)': 0.92, 'Reasonable (R)': 0.96, 'Confirmed (C)': 1}

    ecm = dict_ecm[ecm_value]
    fix = dict_fix[fix_value]
    conf = dict_conf[confidence_value]

    new_cvss_score = cvss_score * ecm * fix * conf

    # arrotonda il nuovo cvss score a un numero con una sola cifra decimale
    new_cvss_score = round(new_cvss_score, 1)
    return new_cvss_score


# Funzione principale
def main():
    # Richiedi una CVE come input da tastiera
    # cve_input = input("Inserisci una CVE (esempio: CVE-2023-1234): ").strip()
    cve_list = [
    "CVE-2021-31166", "CVE-2023-38185", "CVE-2020-12048", "CVE-2021-41773",
    "CVE-2021-4034", "CVE-2021-34527", "CVE-2024-0012", "CVE-2021-21985",
    "CVE-2020-12021", "CVE-2021-24017", "CVE-2013-1414", "CVE-2015-3615",
    "CVE-2024-47574", "CVE-2016-4965", "CVE-2023-47536", "CVE-2023-36554",
    "CVE-2023-46712", "CVE-2021-24018", "CVE-2023-42791", "CVE-2021-22127",
    "CVE-2022-45860", "CVE-2024-35279", "CVE-2017-7344", "CVE-2022-1807",
    "CVE-2021-25268", "CVE-2024-0008", "CVE-2022-3713", "CVE-2024-12728",
    "CVE-2024-9474", "CVE-2015-7547", "CVE-2020-2050", "CVE-2025-0108",
    "CVE-2023-6795", "CVE-2022-0024", "CVE-2022-3353", "CVE-2023-4518",
    "CVE-2022-38138", "CVE-2024-34057", "CVE-2016-4524", "CVE-2018-13798",
    "CVE-2022-29884", "CVE-2021-35534", "CVE-2021-27196", "CVE-2023-34390",
    "CVE-2023-34388", "CVE-2024-7587", "CVE-2023-2310", "CVE-2023-31177",
    "CVE-2023-31152", "CVE-2019-10974", "CVE-2024-11155", "CVE-2023-4518",
    "CVE-2024-5000", "CVE-2024-8175"
    ]
    
    for cve_input in cve_list:
        # Controlla che l'input non sia vuoto
        # if not cve_input:
        # print("[!] Errore: nessuna CVE fornita.")
        # exit(1)
        print(f"[i] CVE fornita: {cve_input}")

        # Ottieni dati CVE da NVD
        cve_data = get_cve_data(cve_input)

        # Estrai CVSS Base Score da CVE
        cvss_score = extract_cvss_base_score(cve_data)
        print(f'CVSS Base Score: {cvss_score}')

        # Ottieni exploit da Exploit DB
        exploitdb_exploits = search_exploitdb_online(cve_input)
        if exploitdb_exploits != []:
            exploitdb_rank = exploitdb_values(exploitdb_exploits)
        else:
            exploitdb_rank = 2

        # Ottieni exploit da PacketStorm
        packetstorm_exploits = search_packetstorm_exploits(cve_input)
        if packetstorm_exploits != []:
            packetstorm_rank = 3
        else:
            packetstorm_rank = 2

        # Ottieni exploit da Metasploit
        metasploit_exploits, metasploit_rank = search_metasploit_exploits(cve_input)

        rank = max(exploitdb_rank, packetstorm_rank, metasploit_rank)
        ecm_level = evaluate_exploit(rank)

        remediation_level = remediation(cve_input)

        confidence = "Confirmed (C)"   # Valore fisso (usando CVE già note)

        new_cvss_score = compute_cvss_score(cvss_score, ecm_level, remediation_level, confidence)
        print(f"Nuovo CVSS Score: {new_cvss_score}")

        # aggiungi i risultati in un file csv con cve_id, cvss_score, ecm, remediation, confidence, new_cvss_score
        with open('/home/kali/Desktop/cve_results.csv', mode='a') as file:
            writer = csv.writer(file)
            writer.writerow([cve_input, cvss_score, ecm_level, remediation_level, confidence, new_cvss_score])


# Esegui il programma
if __name__ == "__main__":
    main()
