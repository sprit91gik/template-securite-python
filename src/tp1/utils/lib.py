# src/tp1/utils/lib.py

import sys
from scapy.all import conf, ifaces, get_if_list
from src.config import logging

logger = logging.getLogger("TP1")

def hello_world() -> str:
    """
    Hello world function (Unused, for TP structure)
    """
    return "hello world"

def choose_interface() -> str:
    """
    Return network interface, asking user choice if multiple interfaces are found, 
    with detailed information (Name, IP, MAC).
    """
    # Utilisation de ifaces pour obtenir une liste détaillée des interfaces
    available_interfaces = list(ifaces.items())
    
    if not available_interfaces:
        logger.error("Aucune interface réseau trouvée. Quittez le programme.")
        sys.exit(1)

    print("\n--- Interfaces disponibles ---")
    
    # Affichage des informations détaillées
    for i, (name, interface_info) in enumerate(available_interfaces):
        ip = interface_info.ip
        mac = interface_info.mac
        
        print(f"  [{i}] Nom: {name}")
        print(f"      - IP : {ip if ip else 'N/A'}")
        print(f"      - MAC: {mac if mac else 'N/A'}")
    print("------------------------------")

    # Logique de choix
    if conf.iface and conf.iface in ifaces:
        # Tente de retourner l'interface par défaut si elle est valide (comme ens33 dans votre cas)
        print(f"Interface par défaut sélectionnée : {conf.iface}")
        return conf.iface
    
    while True:
        try:
            choice = input(f"Choisissez une interface (0-{len(available_interfaces)-1} ou nom exact): ")
            
            # 1. Si l'utilisateur a entré un nom d'interface complet
            if choice in ifaces:
                return choice
            
            # 2. Si l'utilisateur a entré un index (chiffre)
            idx = int(choice)
            if 0 <= idx < len(available_interfaces):
                return available_interfaces[idx][0]
            
        except ValueError:
            pass
            
        print("Choix invalide. Veuillez entrer l'index ou le nom exact de l'interface.")
