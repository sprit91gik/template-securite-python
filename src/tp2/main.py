import argparse
import logging
import sys
from .utils.analyzer import (
    get_shellcode_strings,
    get_pylibemu_analysis,
    get_capstone_analysis,
    get_llm_analysis
)

# Configuration du logging pour correspondre au format attendu : <Logger> - message
logging.basicConfig(level=logging.INFO, format='<Logger> - %(message)s')
logger = logging.getLogger(__name__)

def main(file_path: str):
    """
    Charge le shellcode, exécute toutes les analyses et affiche le rapport final.
    """
    shellcode_data = b''
    
    try:
        # Chargement du shellcode en mode binaire ('rb')
        with open(file_path, 'rb') as f:
            shellcode_data = f.read()

        if not shellcode_data:
            logger.error(f"Le fichier '{file_path}' est vide ou illisible. Fin de l'analyse.")
            return

        logger.info(f"Testing shellcode of size {len(shellcode_data)}B")

        # --- Exécution des Analyses (4 étapes) ---

        # 1. Extraction des chaînes
        strings = get_shellcode_strings(shellcode_data) 

        # 2. Analyse Pylibemu (Retourne l'erreur ou un résultat)
        api_analysis_output = get_pylibemu_analysis(shellcode_data)
        if api_analysis_output:
            print(api_analysis_output)
            
        # 3. Analyse Capstone (Désassemblage réel)
        instructions_analysis = get_capstone_analysis(shellcode_data)
        
        # Affichage du Désassemblage
        print("\n<Logger> - Shellcode instructions:\n")
        for instr in instructions_analysis:
            print(instr)

        # 4. Analyse LLM (Interprétation réelle)
        llm_output = get_llm_analysis(
            strings, 
            instructions_analysis, 
            api_analysis_output
        )
        
        # --- Affichage Final ---
        logger.info("\nShellcode analysed !")
        print(f"\n<Logger> - Explication LLM : {llm_output}")

    except FileNotFoundError:
        logger.error(f"Erreur: Fichier introuvable à l'emplacement : {file_path}")
    except Exception as e:
        logger.error(f"Une erreur inattendue est survenue : {e}")

def main_entry_point():
    """
    Point d'entrée principal appelé par Poetry.
    """
    parser = argparse.ArgumentParser(
        description="Programme d'analyse de shellcode avec outils d'ingénierie inverse et LLM."
    )
    # L'argument -f/--file est obligatoire
    parser.add_argument(
        "-f", 
        "--file", 
        type=str, 
        required=True,
        help="Chemin vers le fichier contenant le shellcode à analyser."
    )
    args = parser.parse_args()
    
    main(args.file)

if __name__ == "__main__":
    main_entry_point()
