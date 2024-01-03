from flask import Flask, request, jsonify
import hashlib
import hmac
import os
import logging
import base64
import psycopg2

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
        LIMIT 75;
        """
        cursor.execute(query, (note_dpe,))
        rows = cursor.fetchall()
    conn.close()
    return rows


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


@app.route('/test-webhook', methods=['POST'])
def test_webhook():
    # Vérifier la signature du webhook
    if not verify_woocommerce_signature(request, woocommerce_secret):
        logger.error("Signature non valide ou manquante dans la requête.")
        return 'Signature non valide', 403

    try:
        # Traitement des données JSON
        data = request.json
        logger.debug("Données JSON reçues : %s", data)

        # Votre logique de traitement ici...

        return 'Webhook traité avec succès', 200
    except Exception as e:
        logger.exception("Erreur lors du traitement du webhook: %s", e)
        return 'Erreur interne du serveur', 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
