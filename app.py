from flask import Flask, request
import hashlib
import hmac
import os
import logging

app = Flask(__name__)

# Configuration de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Variables d'environnement
host = os.environ.get('REDSHIFT_HOST')
port = os.environ.get('REDSHIFT_PORT')
dbname = os.environ.get('REDSHIFT_DBNAME')
user = os.environ.get('REDSHIFT_USER')
password = os.environ.get('REDSHIFT_PASSWORD')
woocommerce = os.environ.get('WCKEY')

def verify_woocommerce_signature(request, woocommerce):
    received_signature = request.headers.get('X-WC-Webhook-Signature')
    request_payload = request.get_data(as_text=True)
    generated_signature = hmac.new(woocommerce.encode(), request_payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(received_signature, generated_signature)

@app.route('/webhook', methods=['POST'])
def webhook():
    if not verify_woocommerce_signature(request, woocommerce):
        logger.error("Signature non valide, requête suspecte")
        return 'Signature non valide', 403

    try:
        # Traitement de la requête
        logger.info("Webhook reçu :")
        logger.info(request.json)
        return '', 200
    except Exception as e:
        logger.exception("Erreur lors du traitement du webhook: %s", e)
        return 'Erreur interne du serveur', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
