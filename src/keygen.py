'''
Questo script contiene la funzione necessaria per la generazione di tutte le chiavi RSA delle entità del prototipo (client+ capo+N escrow agents).
La funzione presente genera delle coppie di chiavi RSA, salvando quelle pubbliche in una cartella e
quelle private in un altra. 
'''

##############
# IMPORT SECTION
##############

from Crypto.PublicKey import RSA
import os

##############
# FUNCTION SECTION
##############

def generate_all_keys(n_agents, public_dir, private_dir):
    os.makedirs(public_dir, exist_ok=True)
    os.makedirs(private_dir, exist_ok=True)
    
    # Entità: agent_1...agent_N + CAPO + Client
    entities = [f"AGENT_{i}" for i in range(1, n_agents + 1)] + ["CAPO", "CLIENT"]
    
    print(f"[KEYGEN] Generazione di {len(entities)} coppie di chiavi...")
    
    for name in entities:
        key = RSA.generate(2048)
        
        # Salvataggio della chiave privata
        priv_path = os.path.join(private_dir, f"{name}_priv.pem")
        with open(priv_path, "wb") as f:
            f.write(key.export_key())
            
        # Salvataggio della chiave pubblica
        pub_path = os.path.join(public_dir, f"{name}_pub.pem")
        with open(pub_path, "wb") as f:
            f.write(key.publickey().export_key())
            
    print(f"[KEYGEN] Generazione completata")
    print(f" -> Chiavi pubbliche in: {public_dir}")
    print(f" -> Chiavi private in: {private_dir}")