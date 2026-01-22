##############
# IMPORT SECTION
##############

import sys
import os
from queue import Queue
from src.keygen import generate_all_keys
from src.entities import ClientThread, AgentThread, CapoThread

##############
# MAIN SECTION
##############

def main():
    if len(sys.argv) < 2:
        print("Utilizzo: python main.py <percorso_supporto_esterno>")
        print("Esempio: python main.py ./external_usb_sim")
        sys.exit(1)

    EXTERNAL_STORAGE = sys.argv[1]
    PUBLIC_STORAGE = "keys/public"
    N, T = 5, 3
    
    # 1. Workflow: Generazione Chiavi
    # Le chiavi private finiscono nel percorso passato da riga di comando
    if not os.path.exists(os.path.join(EXTERNAL_STORAGE, "CAPO_priv.pem")):
        print("[SYSTEM] Inizializzazione chiavi sui supporti...")
        generate_all_keys(N, PUBLIC_STORAGE, EXTERNAL_STORAGE)
    
    # 2. Setup Canali di Comunicazione
    agent_qs = [Queue() for _ in range(N)]
    capo_q = Queue()
    
    # 3. Lancio Entità
    agents = [AgentThread(i, agent_qs[i-1], capo_q, EXTERNAL_STORAGE) for i in range(1, N+1)]
    capo = CapoThread(T, agent_qs, capo_q, EXTERNAL_STORAGE)
    client = ClientThread(N, T, agent_qs)
    
    for a in agents: 
        a.daemon = True
        a.start()
    
    capo.start()
    client.start()
    
    # Il main attende la conclusione del Capo e del Client
    client.join()
    capo.join()
    print("\n[SYSTEM] Simulazione terminata correttamente.")

if __name__ == "__main__":
    main()