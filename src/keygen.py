##############
# IMPORT SECTION
##############

from Crypto.PublicKey import RSA
import os

def generate_all_keys(n_agents, public_dir, private_external_dir):
    """Genera coppie RSA e le salva in percorsi differenti."""
    os.makedirs(public_dir, exist_ok=True)
    os.makedirs(private_external_dir, exist_ok=True)
    
    entities = [f"agent_{i}" for i in range(1, n_agents + 1)] + ["CAPO"]
    
    for name in entities:
        key = RSA.generate(2048)
        # Supporto Esterno (Private)
        with open(os.path.join(private_external_dir, f"{name}_priv.pem"), "wb") as f:
            f.write(key.export_key())
        # Supporto Locale (Pubbliche)
        with open(os.path.join(public_dir, f"{name}_pub.pem"), "wb") as f:
            f.write(key.publickey().export_key())
    
    print(f"[KEYGEN] Chiavi generate con successo.")