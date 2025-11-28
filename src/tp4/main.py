from pwn import *
import base64

# --- CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 8080      

# Affiche tous les échanges pour voir ce qu'il se passe (utile pour le debug)
context.log_level = 'debug'

def solve():
    # Connexion au serveur
    try:
        conn = remote(HOST, PORT)
    except:
        print("❌ Impossible de se connecter. Vérifie l'IP et le Port.")
        return

    # Boucle infinie pour traiter les challenges à la chaine
    while True:
        try:
            # 1. Recevoir les données
            # recvline() lit jusqu'au saut de ligne '\n'. 
            # Parfois il faut utiliser recvuntil(':') si le serveur attend un prompt.
            data = conn.recvline().strip() 
            
            # Si le serveur envoie du texte vide ou ferme la connexion
            if not data:
                print("Fin des données ou connexion fermée.")
                break

            print(f"Reçu (brut): {data}")

            # 2. Nettoyage (Si le serveur envoie du texte avant le code)
            # Parfois le serveur envoie : "Decode this : <BASE64>"
            # Il faut isoler la partie base64. 
            # Exemple simple si le serveur n'envoie QUE du base64 :
            to_decode = data 
            
            # 3. Décodage
            try:
                decoded = base64.b64decode(to_decode)
                print(f"Décodé : {decoded}")
            except Exception as e:
                print(f"Erreur de décodage: {e}")
                # Si ça échoue, c'est peut-être qu'on a reçu le FLAG !
                # On passe en mode interactif pour lire le flag manuellement
                conn.interactive()
                break

            # 4. Envoi de la réponse
            conn.sendline(decoded)
            
        except EOFError:
            # Le serveur a coupé la connexion (souvent après avoir donné le flag)
            print("Server closed connection. Check logs above for the flag!")
            break
        except KeyboardInterrupt:
            conn.close()
            break

if __name__ == "__main__":
    solve()
