# src/tp1/utils/capture.py

import sys
import os
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Raw
from collections import defaultdict
from src.tp1.utils.lib import choose_interface
from src.config import logging

logger = logging.getLogger("TP1")

class Capture:
    def __init__(self, duration: int = 30) -> None:
        self.interface = choose_interface()
        self.duration = duration
        self.protocol_stats = defaultdict(int)
        # Utiliser un dictionnaire pour stocker l'alerte unique et son compteur
        # Format: {'Type_IP_MotCle': {'count': N, 'details': '...'}}
        self.alerts_counter = {}

    def _log_attack(self, attack_type: str, attacker_net_info: str, details: str):
        """
        Enregistre l'attaque, la déduplique ou incrémente son compteur.
        """
        # Créer une clé unique pour cette attaque (Protocole + IP + Signature)
        key = f"{attack_type}_{attacker_net_info.split(',')[0].strip()}_{details}"
        
        if key in self.alerts_counter:
            self.alerts_counter[key]['count'] += 1
        else:
            self.alerts_counter[key] = {
                'count': 1,
                'type': attack_type,
                'net_info': attacker_net_info,
                'details': details
            }
            # N'afficher l'alerte WARNING que la première fois pour éviter les milliers de lignes
            logger.warning(f"NOUVELLE ALERTE : {attack_type} depuis {attacker_net_info}. Détail: {details}")

    def _block_attacker(self, ip_address: str):
        """ (FACULTATIF) Opérer le blocage de la machine attaquante. """
        pass 

    def _analyze_arp(self, packet):
        """Analyse simplifiée des paquets ARP pour détection de Spoofing."""
        # Logique d'alerte ARP Spoofing (si implémentée)
        pass

    def _analyze_tcp_payload(self, packet):
        """Analyse des charges utiles TCP pour des signatures d'injection (uniquement HTTP clair)."""
        
        # FILTRE CRITIQUE: Vérifier uniquement le port 80 (HTTP) pour réduire les faux positifs
        if not packet.haslayer(TCP) or (packet[TCP].dport != 80 and packet[TCP].sport != 80):
            return
            
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                sqli_keywords = ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "--"]
                
                for keyword in sqli_keywords:
                    if keyword in payload.upper(): # Vérification insensible à la casse
                        src_ip = packet[IP].src if packet.haslayer(IP) else "Inconnue"
                        src_mac = packet.src
                        attacker_net_info = f"IP: {src_ip}, MAC: {src_mac}"
                        
                        self._log_attack("Injection SQL", attacker_net_info, keyword)
                        self._block_attacker(src_ip)
                        break
            except Exception:
                pass

    def _process_packet(self, packet):
        """Fonction de rappel principale pour chaque paquet capturé"""
        
        # 1. Identifier et Compter les protocoles
        if packet.haslayer(ARP):
            self.protocol_stats['ARP'] += 1
            self._analyze_arp(packet)
        elif packet.haslayer(ICMP):
            self.protocol_stats['ICMP'] += 1
        elif packet.haslayer(TCP):
            self.protocol_stats['TCP'] += 1
            self._analyze_tcp_payload(packet)
        elif packet.haslayer(UDP):
            self.protocol_stats['UDP'] += 1
        elif packet.haslayer(IP):
            self.protocol_stats['IP_OTHER'] += 1
        else:
            self.protocol_stats['OTHER'] += 1

    def capture_traffic(self) -> None:
        """
        Capture le trafic réseau pendant la durée spécifiée.
        """
        logger.info(f"Démarrage de la capture sur {self.interface} pour {self.duration} secondes...")
        try:
            sniff(iface=self.interface, prn=self._process_packet, timeout=self.duration, store=0)
        except PermissionError:
            logger.error("Capture échouée : Vous n'avez pas les droits root/administrateur.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Erreur de capture : {e}")
            sys.exit(1)

    def get_all_protocols(self) -> defaultdict:
        """Retourne toutes les statistiques de protocoles capturées."""
        return self.protocol_stats
    
    def get_alerts(self) -> dict:
        """Retourne le dictionnaire des alertes comptées."""
        return self.alerts_counter

    def analyse(self) -> str:
        """
        Fonction principale d'analyse et de résumé.
        """
        total_alerts = sum(item['count'] for item in self.alerts_counter.values())
        if total_alerts > 0:
            return f"ALERTE : {total_alerts} tentatives d'attaque détectées ({len(self.alerts_counter)} types uniques)."
        else:
            return "Trafic analysé : OK."
