# main.py
from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    logger.info("Starting TP3")

    # ATTENTION : Remplacer par l'IP et le port de votre serveur de défi !
    ip = "31.220.95.27:9002" 
    challenges = {
        "1": f"http://{ip}/captcha1/",
        # Ajouter les autres challenges au fur et à mesure
        # "2": f"http://{ip}/captcha2/", 
    } 

    for i in challenges:
        logger.info(f"--- Starting Challenge {i} ---")
        url = challenges[i]
        session = Session(url)
        
        # Le loop s'assure de retenter tant que process_response() retourne False
        while not session.process_response():
            session.prepare_request()
            session.submit_request()

        logger.info("Smell good !")
        logger.info(f"Flag for {url} : {session.get_flag()}")


if __name__ == "__main__":
    main()
