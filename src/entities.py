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
    def __init__(self, n, t, agent_queues):
        super().__init__(name="Client")
        self.n, self.t, self.queues = n, t, agent_queues

    def run(self):
        print(f"[{self.name}] Avvio: generazione segreto...")
        key = generate_aes_key()
        shares = split_key(key, self.t, self.n)
        
        for idx, s_hex in shares:
            packet = f"{idx}:{s_hex}".encode()
            # Cifratura per l'agente tramite chiave pubblica locale
            enc_packet = rsa_encrypt(packet, f"keys/public/agent_{idx}_pub.pem")
            self.queues[idx-1].put(enc_packet)
        print(f"[{self.name}] Deposito completato.")

class AgentThread(threading.Thread):
    def __init__(self, agent_id, my_q, capo_q, private_dir):
        super().__init__(name=f"Agent_{agent_id}")
        self.id = agent_id
        self.my_q = my_q
        self.capo_q = capo_q
        self.private_key_path = os.path.join(private_dir, f"agent_{agent_id}_priv.pem")
        self.vault = None

    def run(self):
        # Fase 1: Ricezione deposito dal Client
        self.vault = self.my_q.get()
        print(f"[{self.name}] Frammento archiviato.")

        # Fase 2: Attesa comando dal Capo
        msg = self.my_q.get()
        if msg == "RELEASE":
            print(f"[{self.name}] Accesso al supporto esterno per decifratura...")
            # Decifra con la privata sul supporto esterno
            raw_share = rsa_decrypt(self.vault, self.private_key_path)
            # Ricifra per il Capo
            to_capo = rsa_encrypt(raw_share, "keys/public/CAPO_pub.pem")
            self.capo_q.put(to_capo)

class CapoThread(threading.Thread):
    def __init__(self, t, agent_qs, my_q, private_dir):
        super().__init__(name="CAPO")
        self.t = t
        self.agent_qs = agent_qs
        self.my_q = my_q
        self.private_key_path = os.path.join(private_dir, "CAPO_priv.pem")

    def run(self):
        time.sleep(2) # Attesa simulata per fine deposito
        print(f"[{self.name}] Richiesta di recupero inviata agli agenti...")
        for q in self.agent_qs:
            q.put("RELEASE")
        
        collected_shares = []
        for _ in range(self.t):
            enc = self.my_q.get()
            # Decifra usando la privata sul supporto esterno
            dec = rsa_decrypt(enc, self.private_key_path).decode()
            idx, val = dec.split(":")
            collected_shares.append((int(idx), val))
            print(f"[{self.name}] Ottenuto frammento da Agente {idx}.")
        
        secret = recover_key(collected_shares)
        print(f"\n[{self.name}] SEGRETO RICOSTRUITO CON SUCCESSO: {secret.decode()}")