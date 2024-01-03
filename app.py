from flask import Flask, request, jsonify
import hashlib
import hmac
import os
import logging
import base64

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

    logger.debug(f"Signature reçue (décodée): {received_signature_bytes}")
    logger.debug(f"Signature générée (bytes): {generated_signature_bytes}")

    return signature_valid




@app.route('/wcwebhook', methods=['POST'])
def webhook():
    # Vérifier si la clé secrète est définie
    if woocommerce_secret is None:
        logger.error("La clé secrète WooCommerce n'est pas définie.")
        return 'Erreur de configuration du serveur', 500

    # Vérifier et traiter la signature du webhook
    if not verify_woocommerce_signature(request, woocommerce_secret):
        logger.error("Signature non valide ou manquante dans la requête.")
        return 'Signature non valide', 403

    try:
        # Traitement de la requête
        order_data = request.json
        logger.info("Webhook reçu avec succès pour une commande.")
        
        # Exemple de données que vous pourriez vouloir logger :
        order_id = order_data.get('id')
        order_status = order_data.get('status')
        order_total = order_data.get('total')
        customer_id = order_data.get('customer_id')
        date_created = order_data.get('date_created')
        items = order_data.get('line_items', [])

        # Créer un résumé de la commande
        order_summary = {
            'Order ID': order_id,
            'Status': order_status,
            'Total': order_total,
            'Customer ID': customer_id,
            'Date Created': date_created,
            'Items': [{'Name': item.get('name'), 'Quantity': item.get('quantity')} for item in items]
        }
        
        # Log le résumé de la commande
        logger.debug("Résumé de la commande : %s", order_summary)

        # Ici, vous pouvez ajouter d'autres traitements, comme stocker les données dans une base de données ou déclencher d'autres actions

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
