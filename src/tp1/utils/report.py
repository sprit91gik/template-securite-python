# src/tp1/utils/report.py

import os
import matplotlib.pyplot as plt
from fpdf import FPDF
from collections import defaultdict
from src.config import logging

logger = logging.getLogger("TP1")

# Couleurs pour les protocoles dans le graphique et le tableau
PROTOCOL_COLORS = {
    'TCP': '#FF5733',  # Rouge vif
    'UDP': '#33FF57',  # Vert pomme
    'ARP': '#3357FF',  # Bleu
    'ICMP': '#FF33A1', # Rose
    'IP_OTHER': '#FFBB33', # Orange
    'OTHER': '#BBBBBB' # Gris
}
REPORT_FILENAME = "rapport_tp1_ids.pdf"

class Report:
    def __init__(self, filename=REPORT_FILENAME) -> None:
        self.filename = filename
        self.title = "Rapport d'Analyse IDS/IPS"
        self.stats = defaultdict(int)
        self.alerts_counter = {}
        self.graph_path = ""
        
    def _generate_graph(self) -> str:
        """Génère un diagramme circulaire des protocoles."""
        labels = list(self.stats.keys())
        sizes = list(self.stats.values())
        colors = [PROTOCOL_COLORS.get(label, '#CCCCCC') for label in labels]

        if not sizes or sum(sizes) == 0:
            return None

        plt.figure(figsize=(8, 8))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors)
        plt.title('Distribution des Protocoles Réseau')
        plt.axis('equal')
        graph_filename = "graph_temp.png"
        plt.savefig(graph_filename)
        plt.close()
        return graph_filename

    def _add_colored_text(self, pdf: FPDF, text: str, color_rgb: tuple, ln=1):
        pdf.set_text_color(*color_rgb)
        pdf.multi_cell(0, 8, text, ln=ln)
        pdf.set_text_color(0, 0, 0) # Réinitialiser au noir

    def save(self, protocol_stats: defaultdict, alerts_counter: dict) -> None:
        """
        Génère et enregistre le rapport PDF.
        """
        self.stats = protocol_stats
        self.alerts_counter = alerts_counter
        self.graph_path = self._generate_graph()

        pdf = FPDF()
        pdf.add_page()
        
        # Titre
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt=self.title, ln=1, align='C')
        pdf.ln(5)

        # 1. Statistiques du Trafic
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="1. Statistiques des Protocoles", ln=1, align='L')
        
        if self.graph_path:
            pdf.image(self.graph_path, x=50, y=35, w=100)
            pdf.ln(110)

        # 2. Tableau des protocoles
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(40, 7, "Protocole", 1, 0, 'C')
        pdf.cell(40, 7, "Paquets", 1, 1, 'C')
        
        pdf.set_font("Arial", '', 10)
        for proto, count in self.stats.items():
            # Conversion des codes hexadécimaux des couleurs en RGB pour fpdf
            pdf.set_fill_color(*[int(PROTOCOL_COLORS.get(proto, '#CCCCCC')[i:i+2], 16) for i in (1, 3, 5)])
            pdf.cell(40, 7, proto, 1, 0, 'L', fill=True)
            pdf.cell(40, 7, str(count), 1, 1, 'C', fill=False)

        # 3. Analyse de Légitimité
        pdf.ln(10)
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="3. Analyse de Sécurité et Légitimité", ln=1, align='L')
        
        total_alerts = sum(item['count'] for item in self.alerts_counter.values())
        
        pdf.set_font("Arial", '', 10)
        if total_alerts == 0:
            self._add_colored_text(pdf, "Trafic analysé : OK. Aucun comportement malveillant détecté.", (0, 150, 0)) # Vert
        else:
            pdf.set_text_color(200, 0, 0) # Rouge
            pdf.multi_cell(0, 10, f"ATTENTION : {total_alerts} tentatives d'attaque détectées ({len(self.alerts_counter)} alertes uniques).")
            pdf.set_text_color(0, 0, 0) # Noir
            
            # Limiter l'affichage des alertes uniques pour ne pas saturer le PDF
            display_limit = 100 
            
            # Trier les alertes par nombre d'occurrences décroissant
            sorted_alerts = sorted(self.alerts_counter.values(), key=lambda x: x['count'], reverse=True)
            
            # --- Affichage des alertes uniques avec décompte ---
            line_height = 5
            
            for i, alert in enumerate(sorted_alerts[:display_limit]):
                
                # Alerte principale (Type et Compteur)
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(0, line_height, txt=f"[{i+1}] {alert['type']} ({alert['count']}x) :", ln=1)
                
                # Informations Attaquant
                pdf.set_font("Arial", '', 9)
                pdf.cell(10) # Décalage (indentation)
                pdf.cell(0, line_height, txt=f"Attaquant: {alert['net_info']}", ln=1)
                
                # Détails de la Signature (utilisation de multi_cell pour les détails potentiellement longs)
                pdf.cell(10) # Décalage (indentation)
                pdf.multi_cell(0, line_height, txt=f"Mot-clé trouvé: {alert['details']}")
                
                pdf.ln(2) # Espace entre les alertes uniques
                
            # --- Message de coupure si trop d'alertes ---
            if len(sorted_alerts) > display_limit:
                 pdf.multi_cell(0, 6, f"  ... et {len(sorted_alerts) - display_limit} autres types d'alertes non affichés.")

        # Sauvegarde et nettoyage
        pdf.output(self.filename)
        logger.info(f"Rapport généré : {self.filename}")
        if self.graph_path and os.path.exists(self.graph_path):
            os.remove(self.graph_path)
