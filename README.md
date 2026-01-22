
# KeyEscrow

<img src="/https://www.google.com/search?q=divisione+sicura+chiavi+crittografiche+escrow&sca_esv=0b64f9733fed06e0&udm=2&biw=1519&bih=714&aic=0&sxsrf=ANbL-n6eb4yWpaCSHwDVk2RqdW1ADF6blQ%3A1769103547921&ei=u2ByacnyN8G5i-gPh7K74Ac&ved=0ahUKEwiJvK2k2J-SAxXB3AIHHQfZDnwQ4dUDCBI&uact=5&oq=divisione+sicura+chiavi+crittografiche+escrow&gs_lp=Egtnd3Mtd2l6LWltZyItZGl2aXNpb25lIHNpY3VyYSBjaGlhdmkgY3JpdHRvZ3JhZmljaGUgZXNjcm93SIUvUI8HWMgrcAF4AJABAJgBPaAB5gmqAQIyMrgBA8gBAPgBAZgCAKACAJgDAIgGAZIHAKAHiAKyBwC4BwDCBwDIBwCACAE&sclient=gws-wiz-img#sv=CAMSVhoyKhBlLUk4MGFCcDQ4XzgxWk9NMg5JODBhQnA0OF84MVpPTToOMTlBazZaa1dUaGtsTk0gBCocCgZtb3NhaWMSEGUtSTgwYUJwNDhfODFaT00YADABGAcgqcvgWTACSgoIAhACGAIgAigC" alt="KeyEscrow Header" width="800"/>

### Un sistema di key escrow simulato che implementa il protocollo di Shamir Secret Sharing per la gestione sicura e distribuita delle chiavi crittografiche.

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![PyCryptodome](https://img.shields.io/badge/PyCryptodome-3.x-orange.svg)](https://www.pycryptodome.org/)

</div>

## 📋 Descrizione

KeyEscrow è un prototipo che dimostra come un sistema di deposito chiavi (key escrow) possa funzionare utilizzando la crittografia a soglia. Il sistema permette di dividere una chiave simmetrica AES in multipli frammenti distribuiti tra diversi agenti fiduciari (escrow agents), garantendo che la chiave possa essere ricostruita solo quando un numero minimo di agenti collabora.

### Caratteristiche Principali

- **Secret Sharing di Shamir**: Divisione della chiave AES in N frammenti con soglia di ricostruzione configurabile
- **Crittografia RSA**: Protezione dei frammenti durante la trasmissione con chiavi pubbliche/private
- **Architettura Multi-Thread**: Simulazione realistica di entità distribuite
- **Padding OAEP**: Prevenzione di attacchi deterministici su RSA
- **Sistema di Verifica**: Controllo simulato dell'integrità della chiave ricostruita


## 📁 Struttura del Progetto

```
KeyEscrow/
├── main.py                 # Entry point del sistema
├── requirements.txt        # Dipendenze Python
├── README.md              # Documentazione
├── src/
│   ├── crypto_utils.py    # Funzioni crittografiche
│   ├── entities.py        # Implementazione delle entità (thread)
│   └── keygen.py          # Generazione chiavi RSA
└── data/
    ├── keys/
    │   ├── public/        # Chiavi pubbliche RSA
    │   └── private/       # Chiavi private RSA
    └── secret             # Chiave AES originale
```

La cartella data è un esempio utilizzato per la prova del prototipo. Essa non è presente nella repository in quanto contiene le chiavi utilizzate dal sistema. 

## 🏗️ Entità interagenti e loro funzionamento

Il sistema è composto da tre entità, simulate come thread distinti:

### 1. Client
- Genera una chiave simmetrica AES-128
- Divide la chiave in N frammenti con soglia di recupero T usando Shamir Secret Sharing
- Cifra ogni frammento con la chiave pubblica del rispettivo escrow agent a cui viene inviato il frammento
- Invia i frammenti agli agenti in modo sicuro

### 2. Escrow Agents (N agenti)
- Ricevono e archiviano i frammenti cifrati in modo sicuro
- Attendono richieste autorizzate di rilascio
- Decifrano i frammenti con le proprie chiavi private
- Ri-cifrano con la chiave pubblica dell'autorità prima dell'invio

### 3. Capo (Autorità di Recupero)
- Invia richieste broadcast agli escrow agents
- Raccoglie almeno T frammenti (soglia)
- Ricostruisce la chiave AES originale
- Verifica l'integrità confrontando con la chiave originale

## 🚀 Installazione

### Prerequisiti

- Python 3.7+
- python3.10-venv
- pip

### Setup

```bash
# Clone del repository
git clone https://github.com/melomatte/KeyEscrow.git
cd KeyEscrow

# Installazione e attivazione venv
python3 -m venv .venv
source .venv/bin/activate

# Installazione dipendenze
pip install -r requirements.txt
```

## 💻 Utilizzo

### Esecuzione Base

```bash
python main.py
```

### Parametri Configurabili

```bash
python main.py --n 5 --t 3 --public data/keys/public --private data/keys/private --secret data/secret
```

#### Parametri Disponibili

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| `--n` | 5 | Numero di escrow agents nel sistema |
| `--t` | 3 | Soglia di ricostruzione (numero minimo di frammenti necessari) |
| `--public` | `data/keys/public` | Directory contenente le chiavi pubbliche |
| `--private` | `data/keys/private` | Directory contenente le chiavi private |
| `--secret` | `data/secret` | Path del file contenente la chiave AES originale |

### Esempi

```bash
# Configurazione con 7 agenti e soglia 4
python main.py --n 7 --t 4

# Configurazione minimale (3 agenti, soglia 2)
python main.py --n 3 --t 2

# Configurazione con path personalizzati
python main.py --public ./keys/pub --private ./keys/priv --secret ./master_key
```

## 🔐 Dettagli Tecnici

### Algoritmi Crittografici

- **AES-128**: Chiave simmetrica da proteggere (128 bit)
- **RSA-2048**: Coppie di chiavi asimmetriche per ogni entità
- **Shamir Secret Sharing**: Schema (t,n)-threshold per divisione della chiave
- **PKCS1_OAEP**: Padding per cifratura RSA

### Flusso di Esecuzione

1. **Inizializzazione**: Generazione delle coppie di chiavi RSA per tutte le entità
2. **Deposito**: 
   - Client genera chiave AES
   - Divisione in N frammenti (t-threshold)
   - Cifratura e invio agli escrow agents
3. **Archiviazione**: Gli agents memorizzano i frammenti cifrati
4. **Recupero**:
   - L'autorità invia richiesta broadcast
   - Gli agents decifrano e re-cifrano i frammenti
   - L'autorità raccoglie t frammenti
   - Ricostruzione e verifica della chiave

### Comunicazione Thread-Safe

Il sistema utilizza `Queue` di Python per garantire comunicazioni thread-safe tra le entità simulate:
- Ogni agent ha una coda dedicata per ricevere messaggi
- Il capo ha una coda per ricevere i frammenti dagli agents
- Tutte le comunicazioni avvengono in modo asincrono

## 🛡️ Considerazioni di Sicurezza

Questo è un **prototipo educativo**. In un sistema di produzione considerare:

- Generazione di chiavi con entropia crittograficamente sicura
- Gestione sicura delle chiavi private (HSM, secure enclaves)
- Autenticazione e autorizzazione degli agents
- Canali di comunicazione autenticati e cifrati (TLS)
- Logging e audit trail delle operazioni
- Protezione contro attacchi timing
- Key rotation e revoca
- Protezione della memoria (memory wiping)

## 📊 Output di Esempio

```
[KEYGEN] Generazione di 7 coppie di chiavi...
[KEYGEN] Generazione completata
[CLIENT] Avvio thread
[CLIENT] Generazione chiave AES per cifratura locale
[CLIENT] Divisione della chiave in 5 frammenti con 3 threshold di recupero
[AGENT_1] Avvio thread. In attesa di frammento dal Client...
[AGENT_1] Frammento ricevuto e archiviato nel vault.
...
[CAPO] Avvio procedura di recupero autorizzata
[CAPO] Ricevuto frammento da escrow agent 1 e decifrato
[CAPO] Ricostruzione della chiave con i 3 frammenti ricevuti
==================================================
[CAPO] Chiave AES originale:  a1b2c3d4e5f67890a1b2c3d4e5f67890
[CAPO] Chiave AES ricostruita: a1b2c3d4e5f67890a1b2c3d4e5f67890
==================================================
[CAPO] RECUPERO ESEGUITO CON SUCCESSO ✅
```

## 👤 Autore

<div align="center">

<a href="https://github.com/melomatte">
  <img src="https://github.com/melomatte.png" width="100" style="border-radius: 50%;" alt="melomatte"/>
</a>

### **melomatte**

[![GitHub](https://img.shields.io/badge/GitHub-melomatte-181717?style=for-the-badge&logo=github)](https://github.com/melomatte)
[![Profile](https://img.shields.io/badge/View_Profile-Profile-blue?style=for-the-badge)](https://github.com/melomatte)

</div>

---
