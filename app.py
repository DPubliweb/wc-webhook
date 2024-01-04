from flask import Flask, request, jsonify
import hashlib
import hmac
import os
import logging
import base64
import csv
import psycopg2
import boto3

app = Flask(__name__)

# Configuration de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Variables d'environnement
host = os.environ.get('REDSHIFT_HOST')
port = os.environ.get('REDSHIFT_PORT')
dbname = os.environ.get('REDSHIFT_DBNAME')
user = os.environ.get('REDSHIFT_USER')
password = os.environ.get('REDSHIFT_PASSWORD')
woocommerce_secret = os.environ.get('WC_KEY')


def get_dpe_data(note_dpe):
    try:
        conn = psycopg2.connect(dbname=dbname, user=user, password=password, host='pw-cluster.cq6jh9anojbf.us-west-2.redshift.amazonaws.com', port=5439)
        print('Début de requête')
        with conn.cursor() as cursor:
            query = """
            SELECT DISTINCT p.n_dpe AS num_dpe, MAX(lastname) AS nom, MAX(firstname) AS prenom,
            MAX(tel_mobile) AS tel_mobile, MAX(email) AS email, MAX(zipcode) AS code_postal,
            MAX(etiquette_dpe) AS note_dpe  
            FROM vw_principale_tel_mobile p
            LEFT JOIN fact_dpe d ON d.n_dpe = p.n_dpe
            WHERE type_batiment = 'maison' AND etiquette_dpe = %s
            GROUP BY p.n_dpe
            LIMIT 5;  -- Réduire la limite à 5 pour les tests
            """
            cursor.execute(query, (note_dpe,))
            rows = cursor.fetchall()
            print('Requête terminée, nombre de lignes récupérées :', len(rows))

            # Afficher les premières lignes pour le débogage
            for row in rows[:5]:  # Limiter l'affichage aux 5 premières lignes
                print(row)

        conn.close()
        write_to_csv(rows, 'dpe_data.csv')
        bucket_name = "data-dpe"
        uploaded = upload_to_s3('dpe_data.csv', bucket_name)
        if uploaded:
            print("Fichier chargé avec succès dans S3.")
        else:
            print("Échec du chargement dans S3.")
        return rows
    except Exception as e:
        print(f"Erreur lors de l'exécution de la requête : {e}")
        return None



def upload_to_s3(file_name, bucket, object_name=None):
    if object_name is None:
        object_name = file_name

    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
    except Exception as e:
        print(f"Erreur lors du chargement sur S3 : {e}")
        return False
    return True


def verify_woocommerce_signature(request, woocommerce_secret):
    # Log tous les en-têtes pour le débogage
    logger.debug("En-têtes reçus : %s", request.headers)

    received_signature_base64 = request.headers.get('X-WC-Webhook-Signature')
    if received_signature_base64 is None:
        logger.error("Aucune signature Webhook WooCommerce trouvée dans les en-têtes.")
        return False


    request_payload = request.get_data(as_text=True)
    logger.debug(f"Corps de la requête pour la génération de la signature: {request_payload}")

    # Décoder la signature reçue de Base64 en bytes
    received_signature_bytes = base64.b64decode(received_signature_base64)
    
    # Générer la signature HMAC en tant que bytes
    generated_signature_bytes = hmac.new(woocommerce_secret.encode(), request_payload.encode(), hashlib.sha256).digest()

    # Comparaison des signatures en bytes
    signature_valid = hmac.compare_digest(received_signature_bytes, generated_signature_bytes)

    #logger.debug(f"Signature reçue (décodée): {received_signature_bytes}")
    #logger.debug(f"Signature générée (bytes): {generated_signature_bytes}")

    return signature_valid

def write_to_csv(data, filename):
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['num_dpe', 'nom', 'prenom', 'tel_mobile', 'email', 'code_postal', 'note_dpe'])
        for row in data:
            writer.writerow(row)



@app.route('/wcwebhook', methods=['POST'])
def webhook():
    if woocommerce_secret is None:
        logger.error("La clé secrète WooCommerce n'est pas définie.")
        return 'Erreur de configuration du serveur', 500

    if not verify_woocommerce_signature(request, woocommerce_secret):
        logger.error("Signature non valide ou manquante dans la requête.")
        return 'Signature non valide', 403

    try:
        order_data = request.json
        items = order_data.get('line_items', [])
        note_dpe_from_order = None
        for item in items:
            item_name = item.get('name', '')
            if '-' in item_name:
                note_dpe_from_order = item_name.split('-')[-1].strip()
                break

        if note_dpe_from_order:
            logger.info(f"Note DPE extraite de la commande : {note_dpe_from_order}")
            dpe_data = get_dpe_data(note_dpe_from_order)
            logger.info(f"Données DPE récupérées : {dpe_data}")
            # Effectuer des actions supplémentaires avec les données DPE si nécessaire
        else:
            logger.error("Aucune note DPE trouvée dans les articles de la commande.")

        return 'Webhook traité avec succès', 200
    except Exception as e:
        logger.exception("Erreur lors du traitement du webhook: %s", e)
        return 'Erreur interne du serveur', 500


    
@app.route('/')
def home():
    return "hello world"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
