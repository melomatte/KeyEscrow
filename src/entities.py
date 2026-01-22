##############
# IMPORT SECTION
##############

import threading
import time
import os
from src.crypto_utils import generate_aes_key, split_key, rsa_encrypt, rsa_decrypt, recover_key

##############
# ENTITIES SECTION
##############

class ClientThread(threading.Thread):
    def __init__(self, n, t, agent_queues, pub_dir, priv_dir, path_secret):
        super().__init__(name="Client")
        self.n = n
        self.t = t
        self.queues = agent_queues
        self.pub_dir = pub_dir
        self.priv_dir = priv_dir
        self.path_secret = path_secret

    def run(self):
        print(f"[{self.name}] Avvio: generazione chiave AES per cifratura locale...")
        # Simula la generazione della chiave che cifra il filesystem
        key = generate_aes_key()

        # --- SALVATAGGIO DELLA CHIAVE NEL FILE 'secret' ---
        try:
            with open(self.path_secret, "wb") as f:
                f.write(key)
            print(f"[{self.name}] Chiave AES salvata correttamente nel file 'secret'.")
        except Exception as e:
            print(f"[{self.name}] Errore durante il salvataggio del file secret: {e}")
        
        print(f"[{self.name}] Divisione della chiave tramite Shamir ({self.t}/{self.n})...")
        shares = split_key(key, self.t, self.n)
        
        for idx, s_hex in shares:
            # Pacchetto dati: "indice:valore_esadecimale"
            packet = f"{idx}:{s_hex}".encode()
            
            # Recupera la chiave pubblica dell'agente destinatario
            pub_key_path = os.path.join(self.pub_dir, f"agent_{idx}_pub.pem")
            
            # Cifra il frammento per l'agente
            enc_packet = rsa_encrypt(packet, pub_key_path)
            
            # Invia il frammento nella coda dell'agente corrispondente
            self.queues[idx-1].put(enc_packet)
            
        print(f"[{self.name}] Deposito completato. Le quote sono state distribuite agli Escrow Agents.")

class AgentThread(threading.Thread):
    def __init__(self, agent_id, my_q, capo_q, pub_dir, priv_dir):
        super().__init__(name=f"Agent_{agent_id}")
        self.id = agent_id
        self.my_q = my_q         # Coda privata dell'agente
        self.capo_q = capo_q     # Coda per rispondere al Capo
        self.pub_dir = pub_dir
        self.priv_path = os.path.join(priv_dir, f"agent_{agent_id}_priv.pem")
        self.vault = None        # Memoria sicura dell'agente

    def run(self):
        # 1. Fase di attesa deposito dal Client
        print(f"[{self.name}] Online. In attesa di frammento dal Client...")
        self.vault = self.my_q.get()
        print(f"[{self.name}] Frammento ricevuto e archiviato nel vault.")

        # 2. Fase di attesa Broadcast dal Capo
        while True:
            msg = self.my_q.get()
            # Verifica se il messaggio è il comando di sblocco dell'autorità
            if msg == "AUTH_RELEASE_CMD_V1":
                print(f"[{self.name}] Richiesta di broadcast ricevuta dal CAPO. Verifica in corso...")
                
                try:
                    # Recupera il proprio frammento usando la chiave privata (supporto esterno)
                    raw_share = rsa_decrypt(self.vault, self.priv_path)
                    
                    # Recupera la chiave pubblica del CAPO per la ricifratura
                    capo_pub_path = os.path.join(self.pub_dir, "CAPO_pub.pem")
                    
                    # Cifra il frammento appositamente per il Capo (Forward Secrecy simulata)
                    secure_transfer_packet = rsa_encrypt(raw_share, capo_pub_path)
                    
                    # Invia il frammento sulla coda del Capo
                    self.capo_q.put(secure_transfer_packet)
                    print(f"[{self.name}] Frammento inviato in modo sicuro al CAPO.")
                    break # L'agente ha terminato il suo compito
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
        
        print(f"\n[{self.name}] Avvio procedura di recupero autorizzata.")
        
        # Inviata richiesta agli agenti
        for q in self.agent_qs:
            q.put("AUTH_RELEASE_CMD_V1")

        collected_shares = []
        while len(collected_shares) < self.threshold:
            encrypted_packet = self.my_q.get()
            try:
                decrypted_data = rsa_decrypt(encrypted_packet, self.priv_path).decode()
                idx, hex_val = decrypted_data.split(":")
                collected_shares.append((int(idx), hex_val))
                print(f"[{self.name}] Ricevuto frammento da Agente {idx}.")
            except Exception as e:
                print(f"[{self.name}] Errore decifratura: {e}")

        # --- RICOSTRUZIONE E VERIFICA ---
        print(f"[{self.name}] Ricostruzione della chiave tramite Shamir...")
        try:
            # Ricostruisce la chiave dai frammenti
            master_secret = recover_key(collected_shares)
            
            # Legge la chiave originale salvata dal Client per il confronto
            if os.path.exists(self.path_secret):
                with open(self.path_secret, "rb") as f:
                    original_secret = f.read()
                
                print(f"\n" + "="*50)
                print(f"[{self.name}] CHIAVE DA FILE 'secret':  {original_secret.hex()}")
                print(f"[{self.name}] CHIAVE RICOSTRUITA:     {master_secret.hex()}")
                print("="*50)

                # Verifica finale
                if master_secret == original_secret:
                    print(f"[{self.name}] ESITO VERIFICA: SUCCESS ✅ (Le chiavi coincidono)")
                else:
                    print(f"[{self.name}] ESITO VERIFICA: FALLITA ❌ (Le chiavi sono diverse)")
            else:
                print(f"[{self.name}] Errore: File 'secret' non trovato per la verifica.")
                print(f"[{self.name}] Chiave ricostruita (Hex): {master_secret.hex()}")

        except Exception as e:
            print(f"[{self.name}] Errore fatale nella ricostruzione: {e}")