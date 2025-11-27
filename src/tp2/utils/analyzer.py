import re
import logging
import os
from typing import List, Optional

# --- TENTATIVE D'IMPORTATION DES LIBRAIRIES D'ANALYSE ---
CAPSTONE_INSTALLED = False
PYLIBEMU_INSTALLED = False 

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CsError
    CAPSTONE_INSTALLED = True
except ImportError:
    pass 
except Exception:
    pass 

# --- TENTATIVE D'IMPORTATION DE L'API GEMINI ---
GENAI_INSTALLED = False
try:
    from google import genai
    from google.genai.errors import APIError
    GENAI_INSTALLED = True
except ImportError:
    pass 

# Configuration du logging
logger = logging.getLogger(__name__)


# --- Fonctions d'Analyse ---

## 1. get_shellcode_strings
def get_shellcode_strings(data: bytes) -> List[str]:
    """
    Retourne les chaînes de caractères ASCII visibles dans le shellcode.
    """
    logger.info("  [1/4] Extraction des chaînes...")
    strings = re.findall(rb'[ -~]{4,}', data)
    return [s.decode('ascii', errors='ignore') for s in strings]


## 2. get_pylibemu_analysis 
def get_pylibemu_analysis(data: bytes) -> Optional[str]:
    """
    Simule l'analyse Pylibemu pour l'émulation, ou retourne un message d'échec.
    """
    logger.info("  [2/4] Analyse Pylibemu (Émulation) en cours...")
    
    if not PYLIBEMU_INSTALLED:
        return (
            "\n<Logger> - [ERREUR PYLIBEMU] Émulation non disponible. "
            "Installez la librairie 'pylibemu' et ses dépendances C ('libemu') "
            "pour activer l'analyse des appels d'API et le décodage des payloads."
        )
        
    return "<Logger> - [Analyse PYLIBEMU] Code à implémenter pour l'émulation réelle."


## 3. get_capstone_analysis 
def get_capstone_analysis(data: bytes) -> List[str]:
    """
    Désassemble le shellcode binaire en utilisant Capstone (si installé).
    """
    logger.info("  [3/4] Analyse Capstone (Désassemblage) en cours...")
    
    if not CAPSTONE_INSTALLED:
        return [
            "<ERREUR CAPSTONE> Désassemblage indisponible. Installez la librairie 'capstone' pour continuer.",
            "Utilisez 'poetry install' pour tenter l'installation de cette dépendance."
        ]

    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = []
        
        for instruction in md.disasm(data, 0x1000):
            instructions.append(f"0x{instruction.address:04x}: \t{instruction.mnemonic}\t{instruction.op_str}")

        if not instructions:
             return ["<Alerte> Désassemblage réussi, mais 0 instruction valide trouvée (Le shellcode est peut-être encodé, ou l'architecture est incorrecte)."]

        return instructions
    
    except CsError as e:
        return [f"<ERREUR CAPSTONE> Échec du désassemblage : {e}"]
    except Exception as e:
        return [f"<ERREUR INATTENDUE> {e}"]


## 4. get_llm_analysis (Implémentation Réelle de l'Appel API)
def get_llm_analysis(strings: List[str], instructions: List[str], api_calls_output: Optional[str]) -> str:
    """
    Appelle l'API Gemini pour interpréter les résultats du désassemblage.
    """
    logger.info("  [4/4] Génération de l'explication LLM...")
    
    # 1. Vérification des conditions d'exécution
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        return (
            "[ERREUR LLM] Explication non disponible. "
            "Veuillez définir la variable d'environnement GEMINI_API_KEY pour activer l'analyse LLM."
        )
    if not GENAI_INSTALLED:
         return (
            "[ERREUR LLM] Librairie 'google-genai' non installée. "
            "Utilisez 'poetry add google-genai' pour l'installer."
        )

    # 2. Construction du Prompt basé sur les résultats réels
    # Tronquer les instructions à 50 lignes pour ne pas surcharger le prompt
    instructions_sample = instructions[:50]
    
    # CORRECTION DE LA SYNTAXE (Ligne 116): Utiliser une variable intermédiaire pour la jointure
    formatted_instructions = '\n'.join(instructions_sample) 
    
    prompt_data = f"""
    En tant qu'analyste en sécurité de haut niveau, effectuez une analyse Pwn de ce shellcode.
    
    Rédigez un rapport **extrêmement concis** (maximum 4 phrases ou une liste à puces), qui couvre :
    1. Le type de shellcode (e.g., loader, reverse shell).
    2. La technique d'encodage probable (e.g., XOR, Metasploit, pas encodé).
    3. Son objectif final (e.g., télécharger et exécuter un fichier).
    4. Le type de vulnérabilité d'exploitation le plus probable.
    
    --- Données d'Analyse ---
    1. Chaînes trouvées: {', '.join(strings)}
    2. Premières instructions désassemblées (via Capstone):
{formatted_instructions}
    ... (Total: {len(instructions)} instructions)
    3. Résultats d'émulation (via Pylibemu - si disponible): {api_calls_output}

    Fournissez votre réponse UNIQUEMENT en français, sans préambule ("Voici l'analyse:") et en utilisant un format facile à lire (liste ou paragraphe court).
    """

    # 3. Appel réel à l'API Gemini
    try:
        client = genai.Client(api_key=gemini_api_key)
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt_data
        )
        
        return response.text

    except APIError as e:
        return f"[ERREUR API GEMINI] Échec de l'appel API. Vérifiez la clé ou les limites. Détail: {e}"
    except Exception as e:
        return f"[ERREUR INATTENDUE LLM] {e}"
