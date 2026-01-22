##############
# INTRODUCTION SECTION
##############

'''
Lo script contiene il main del prototipo. Legge i parametri da stdin (tutti presentano un default)
e procede a creare i canali per la comunicazione tra le entità (simulate come thread), che vengono
successivamente messe in esecuzione
'''

##############
# IMPORT SECTION
##############

import argparse
from queue import Queue
from src.keygen import generate_all_keys
from src.entities import ClientThread, AgentThread, CapoThread

##############
# MAIN SECTION
##############

def main():
    parser = argparse.ArgumentParser(description="Simulazione sistema key escrow")
    parser.add_argument("--public", default="data/keys/public", help="Cartella dove verranno salvate chiavi pubbliche per l'esecuzione del prototipo")
    parser.add_argument("--private", default="data/keys/private", help="Cartella dove verranno salvate le chiavi private per l'esecuzione del prototipo ")
    parser.add_argument("--secret", default="data/secret", help="Nome del file dove viene salvata la chiave AES generata dal client")
    parser.add_argument("--n", type=int, default=5, help="Numero di escrow agent generato dal sistema (ad ogni escrow agent viene assegnata una parte della chiave AES)")
    parser.add_argument("--t", type=int, default=3, help="Soglia di treshold, numero di escrow agent necessri per ricostruire il segreto")
    args = parser.parse_args()

    # Generazione delle chiavi tramite lo script keygen.py
    generate_all_keys(args.n, args.public, args.private)
    
    # Setup Canali di Comunicazione
    agent_qs = [Queue() for _ in range(args.n)]
    capo_q = Queue()
    
    # Lancio entità del sistema
    agents = [AgentThread(i, agent_qs[i-1], capo_q, args.public, args.private) for i in range(1, args.n+1)]
    capo = CapoThread(args.t, agent_qs, capo_q, args.public, args.private, args.secret)
    client = ClientThread(args.n, args.t, agent_qs, args.public, args.private, args.secret)
    
    for a in agents:
        a.daemon = True
        a.start()
    
    client.start()
    capo.start()
    
    client.join()
    capo.join()

if __name__ == "__main__":
    main()