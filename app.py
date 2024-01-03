from flask import Flask, request
import hashlib
import hmac
import os
import logging

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
woocommerce_secret = os.environ.get('WCKEY')

def verify_woocommerce_signature(request, woocommerce_secret):
    received_signature = request.headers.get('X-WC-Webhook-Signature')
    request_payload = request.get_data(as_text=True)
    generated_signature = hmac.new(woocommerce_secret.encode(), request_payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(received_signature, generated_signature)

@app.route('/wcwebhook', methods=['POST'])
def webhook():
    if not verify_woocommerce_signature(request, woocommerce_secret):
        logger.error("Signature non valide, requête suspecte")
        return 'Signature non valide', 403

    try:
        # Traitement de la requête
        logger.debug("Webhook reçu :")
        logger.debug(request.json)
        return 'Webhook reçu avec succès', 200
    except Exception as e:
        logger.exception("Erreur lors du traitement du webhook: %s", e)
        return 'Erreur interne du serveur', 500
    
@app.route('/')
def home():
    return "hello world"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
