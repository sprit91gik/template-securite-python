# src/tp1/main.py

import sys
from src.tp1.utils.capture import Capture
from src.tp1.utils.report import Report
from src.config import logging

logger = logging.getLogger("TP1")

def main():
    """
    Fonction principale lancée par 'poetry run tp1'.
    """
    logger.info("Démarrage du système d'analyse TP1 (IDS/IPS)...")
    
    # 1. Initialisation de la capture (choix de l'interface)
    try:
        # Capture pendant 30 secondes
        capture = Capture(duration=30) 
    except Exception as e:
        logger.critical(f"Erreur d'initialisation : {e}")
        sys.exit(1)

    # 2. Capture du trafic
    capture.capture_traffic()

    # 3. Analyse et Résumé
    summary_message = capture.analyse()
    logger.info(f"Résumé de l'analyse : {summary_message}")

    # 4. Génération du rapport PDF
    report = Report()
    report.save(capture.get_all_protocols(), capture.get_alerts())
    
    logger.info("Analyse complète terminée.")


if __name__ == "__main__":
    main()
