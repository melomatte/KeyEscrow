##############
# INTRODUCTION SECTION
##############

'''
Questo script contiene il codice eseguito da ogni entità per lo svolgimento del prototipo. 
Le entità presenti sono le seguenti:
    - Client = il client genera una chiave simmetrica e la salva il un file 
    (necessario per eseguire il controllo del recupero da parte del capo). Tale chiave viene divisa
    in N frammenti tramite metodo di Shamir e ciascun frammento viene inviato in maniera cifrata
    ad un differente escrow agent tramite l'utilizzo della rispettiva chiave pubblica del destinatario.
    
    - Escrow agent = attende la ricezione del frammento da parte dell'utente e lo salva in un posto
    sicuro. Successivamente attende la ricezione della richiesta di recupero da parte del capo. Una
    volta ricevuta, decifra il frammento con la propria chiave privata, lo cifra con la chiave pubblica
    del capo e lo invia al capo stesso. 

    - Capo = dopo un periodo di attesa in cui si simula il deposito dei frammenti, il capo invia una
    richiesta in broadcast agli escrow agents richiedendo l'invio dei frammenti. I primi t frammenti
    ricevuti vengono decifrati attraverso la chiave privata e utilizzati per la ricostruzione 
    della chiave simmetrica. Questa viene confratata con quella salvata per evidenziare come è andato
    il processo di ricostruzione     
'''

##############
# IMPORT SECTION
##############

import threading
import time
import os
from . import crypto_utils

##############
# ENTITIES SECTION
##############

class ClientThread(threading.Thread):
    def __init__(self, n, t, agent_queues, pub_dir, priv_dir, path_secret):
        super().__init__(name="CLIENT")
        self.n = n
        self.t = t
        self.queues = agent_queues
        self.pub_dir = pub_dir
        self.priv_dir = priv_dir
        self.path_secret = path_secret

    def run(self):
        print(f"[{self.name}] Avvio thread")
        print(f"[{self.name}] Generazione chiave AES per cifratura locale")
        key = crypto_utils.generate_aes_key()

        # Salvataggio chiave AES nel file (per il confronto con il recupero che deve svolgere il capo)
        try:
            with open(self.path_secret, "wb") as f:
                f.write(key)
            print(f"[{self.name}] Chiave AES salvata correttamente nel file {self.path_secret}.")
        except Exception as e:
            print(f"[{self.name}] Errore durante il salvataggio del file secret: {e}")
        
        # Divisione della chiave in N frammenti
        print(f"[{self.name}] Divisione della chiave in {self.n} frammenti con {self.t} threshold di recupero")
        shares = crypto_utils.split_key(key, self.t, self.n)
        
        # Invio dei frammenti agli N escrow agents, cifrati con la chiave pubblica dell'agent destinatario
        # Ogni frammento viene inviato come: "indice:valore_esadecimale"
        for idx, s_hex in shares:
            packet = f"{idx}:{s_hex}".encode()
            pub_key_path = os.path.join(self.pub_dir, f"AGENT_{idx}_pub.pem")
            enc_packet = crypto_utils.rsa_encrypt(packet, pub_key_path)
            print(f"[{self.name}] Invio del frammento {idx} all'escrow agent {idx}, cifrato con la sua chiave pubblica {pub_key_path}")
            self.queues[idx-1].put(enc_packet)
            
        print(f"[{self.name}] Deposito completato. I frammenti sono stati inviati agli Escrow Agents.")

class AgentThread(threading.Thread):
    def __init__(self, agent_id, my_q, capo_q, pub_dir, priv_dir):
        super().__init__(name=f"AGENT_{agent_id}")
        self.id = agent_id
        self.my_q = my_q         # Coda privata dell'agente
        self.capo_q = capo_q     # Coda per rispondere al Capo
        self.pub_dir = pub_dir
        self.priv_path = os.path.join(priv_dir, f"AGENT_{agent_id}_priv.pem")
        self.vault = None        # Memoria sicura dell'agente

    def run(self):
        print(f"[{self.name}] Avvio thread. In attesa di frammento dal Client...")
        self.vault = self.my_q.get()
        print(f"[{self.name}] Frammento ricevuto e archiviato nel vault.")

        # Attesa attiva ricezione richiesta recupero da parte del capo
        while True:
            msg = self.my_q.get()
            # Verifica se il messaggio è il comando di sblocco dell'autorità
            # In caso positivo, il frammento viene decifrato con la chiave private dell'agent, cifrato con la chiave pubblica del CAPO e inviata al CAPO
            if msg == "AUTH_RELEASE_CMD_V1":
                print(f"[{self.name}] Richiesta di broadcast ricevuta dal CAPO")
                
                try:
                    print(f"[{self.name}] Decifratura con chiave privata del frammento memorizzato")
                    raw_share = crypto_utils.rsa_decrypt(self.vault, self.priv_path)
                    capo_pub_path = os.path.join(self.pub_dir, "CAPO_pub.pem")
                    secure_transfer_packet = crypto_utils.rsa_encrypt(raw_share, capo_pub_path)
                    print(f"[{self.name}] Invio del frammento al CAPO, cifrato con la sua chiave pubblica {capo_pub_path} ")
                    self.capo_q.put(secure_transfer_packet)
                    print(f"[{self.name}] Frammento inviato in modo sicuro al CAPO")
                    break
                except Exception as e:
                    print(f"[{self.name}] Errore durante il rilascio: {e}")
                    break

class CapoThread(threading.Thread):
    def __init__(self, t, agent_qs, my_q, pub_dir, priv_dir, path_secret):
        super().__init__(name="CAPO")
        self.threshold = t
        self.agent_qs = agent_qs
        self.my_q = my_q
        self.pub_dir = pub_dir
        self.priv_path = os.path.join(priv_dir, "CAPO_priv.pem")
        self.path_secret = path_secret

    def run(self):
        # Attesa per simulare il tempo del deposito
        time.sleep(10)

        # Inizio procedura di recupero
        print(f"[{self.name}] Avvio procedura di recupero autorizzata, invio in broadcast della richiesta agli escrow agents")
        for q in self.agent_qs:
            q.put("AUTH_RELEASE_CMD_V1")

        # Ricezione di t frammenti dagli escrow agents per la ricostruzione della chiave AES
        collected_shares = []
        while len(collected_shares) < self.threshold:
            encrypted_packet = self.my_q.get()
            try:
                decrypted_data = crypto_utils.rsa_decrypt(encrypted_packet, self.priv_path).decode()
                idx, hex_val = decrypted_data.split(":")
                collected_shares.append((int(idx), hex_val))
                print(f"[{self.name}] Ricevuto frammento da escrow agent {idx} e decifrato con chiave privata")
            except Exception as e:
                print(f"[{self.name}] Errore decifratura: {e}")

        # Ricostruzione e verifica con la chiave salvata nel file self.path_secret
        print(f"[{self.name}] Ricostruzione della chiave con i {self.threshold} frammenti ricevuti")
        try:
            master_secret = crypto_utils.recover_key(collected_shares)
            
            if os.path.exists(self.path_secret):
                with open(self.path_secret, "rb") as f:
                    original_secret = f.read()
                
                print(f"\n" + "="*50)
                print(f"[{self.name}] Chiave AES contenuta nel file {self.path_secret}:  {original_secret.hex()}")
                print(f"[{self.name}] Chiave AES ricostruita:     {master_secret.hex()}")
                print("="*50)

                if master_secret == original_secret:
                    print(f"[{self.name}] RECUPERO ESEGUITO CON SUCCESSO ✅ (Le chiavi coincidono)")
                else:
                    print(f"[{self.name}] RECUPERO FALLITO ❌ (Le chiavi sono diverse)")
            else:
                print(f"[{self.name}] Errore: File {self.path_secret} non trovato per la verifica.")
                print(f"[{self.name}] Chiave ricostruita (Hex): {master_secret.hex()}")

        except Exception as e:
            print(f"[{self.name}] Errore fatale nella ricostruzione: {e}")