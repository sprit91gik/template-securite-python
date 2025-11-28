# utils/session.py
import requests # Ajout de l'import
import re # Nécessaire pour extraire le flag
from src.tp3.utils.config import logger
from src.tp3.utils.captcha import Captcha


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.
    ...
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.
        ...
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.response = None # Stocke la dernière réponse HTTP

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        # Le flag_value est souvent un simple identifiant pour le début du TP
        self.flag_value = "CAPTCHA_SOLVER"
        logger.debug(f"Prepared request for {self.url} with CAPTCHA: {self.captcha_value}")

    def submit_request(self):
        """
        Sends the flag and captcha.
        Le serveur attend généralement la soumission à l'URL du challenge.
        """
        # Pour CAPTCHA 1, l'endpoint de soumission est l'URL de base
        submission_url = self.url 
        
        # Le format de la soumission est généralement en POST
        payload = {
            "captcha": self.captcha_value,
            "flag": self.flag_value,
        }
        
        try:
            self.response = requests.post(submission_url, data=payload)
            self.response.raise_for_status() # Check for bad status codes
            logger.info(f"Submitted CAPTCHA solution to {submission_url}")
        except requests.RequestException as e:
            logger.error(f"Error submitting request: {e}")
            self.response = None

    def process_response(self):
        """
        Processes the response. Retourne True si le flag est validé/obtenu.
        """
        if self.response is None:
            return False
            
        response_text = self.response.text
        
        # Le serveur signale la réussite avec un message ou le flag directement
        if "Correct" in response_text or "FLAG{" in response_text:
            # Tenter d'extraire le flag (pattern commun pour les CTF)
            flag_match = re.search(r'(FLAG\{[a-zA-Z0-9_\-!@#$%\^&*()]*\})', response_text)
            
            if flag_match:
                self.valid_flag = flag_match.group(1)
                return True
            else:
                # Si 'Correct' mais le flag n'est pas trouvé (passé au challenge suivant ?)
                return True 
        
        # Si la soumission a échoué (CAPTCHA incorrect)
        logger.warning(f"CAPTCHA incorrect. Trying again. Response snippet: {response_text[:100]}...")
        return False

    def get_flag(self):
        """
        Returns the valid flag.
        ...
        """
        return self.valid_flag
