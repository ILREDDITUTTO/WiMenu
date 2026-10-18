#!/usr/bin/env python3
import os
import sys
import subprocess

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Errore nell'esecuzione del comando: {cmd}")
        sys.exit(1)

def main():
    if os.geteuid() != 0:
        print("[!] Errore: Devi eseguire lo script con i permessi di root (sudo python3 install.py)")
        sys.exit(1)

    print("[+] Aggiornamento pacchetti e installazione dipendenze...")
    run_cmd("apt update && apt install python3-scapy python3-pip -y")

    if not os.path.exists("wimenu.py"):
        print("[-] Errore: file wimenu.py non trovato nella cartella corrente.")
        sys.exit(1)

    print("[+] Copia di wimenu in /usr/local/bin/wimenu...")
    run_cmd("cp wimenu.py /usr/local/bin/wimenu")
    run_cmd("chmod +x /usr/local/bin/wimenu")

    print("\n[SUCCESS] Installazione completata con successo!")
    print("[+] Ora puoi avviare il tool da qualsiasi posizione digitando: sudo wimenu\n")

if __name__ == "__main__":
    main()
