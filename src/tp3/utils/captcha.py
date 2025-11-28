# utils/captcha.py
from PIL import Image
import pytesseract
import io
import requests
from src.tp3.utils.config import logger # Assuming logger is correctly imported

class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = None
        self.value = ""

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        if self.image:
            # Tenter l'OCR. Pour CAPTCHA 1, la configuration par défaut devrait suffire.
            # config='--psm 8' peut aider si le texte est une seule ligne/un seul mot.
            try:
                self.value = pytesseract.image_to_string(self.image, config='--psm 8')
                # Nettoyer la valeur (enlever les espaces, caractères non-alphanumériques)
                self.value = ''.join(filter(str.isalnum, self.value)).strip().upper()
                logger.info(f"CAPTCHA solved: {self.value}")
            except Exception as e:
                logger.error(f"Error during OCR: {e}")
                self.value = ""
        else:
            logger.warning("No image captured, cannot solve.")
            self.value = ""

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        Le serveur sert l'image directement à l'URL du challenge.
        """
        try:
            # Utiliser requests.get pour télécharger le contenu binaire de l'image
            response = requests.get(self.url, stream=True)
            response.raise_for_status() # Lève une exception pour les codes 4xx/5xx

            # Ouvrir l'image en mémoire avec PIL
            self.image = Image.open(io.BytesIO(response.content))
            logger.info(f"CAPTCHA image successfully captured from {self.url}")
        except requests.RequestException as e:
            logger.error(f"Error fetching captcha image from {self.url}: {e}")
            self.image = None

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
