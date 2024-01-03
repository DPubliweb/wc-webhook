from flask import Flask, request
import hashlib
import hmac
import os


app = Flask(__name__)
host = os.environ.get('REDSHIFT_HOST')
port = os.environ.get('REDSHIFT_PORT')
dbname = os.environ.get('REDSHIFT_DBNAME')
user = os.environ.get('REDSHIFT_USER')
password = os.environ.get('REDSHIFT_PASSWORD')
woocommerce = os.environ.get('WCKEY')

#def create_redshift_connection():
#    return psycopg2.connect(
#        host='pw-cluster.cq6jh9anojbf.us-west-2.redshift.amazonaws.com',
#        port=5439,
#        dbname=dbname,
#        user=user,
#        password=password
#)


def verify_woocommerce_signature(request, woocommerce):
    # Récupérer la signature envoyée dans les en-têtes
    received_signature = request.headers.get('X-WC-Webhook-Signature')

    # Calculer votre propre signature avec la charge utile et la clé secrète
    request_payload = request.get_data(as_text=True)
    generated_signature = hmac.new(woocommerce.encode(), request_payload.encode(), hashlib.sha256).hexdigest()

    # Comparer les deux signatures
    return hmac.compare_digest(received_signature, generated_signature)

@app.route('/webhook', methods=['POST'])
def webhook():
    if not verify_woocommerce_signature(request, woocommerce):
        print("Signature non valide, requête suspecte")
        return 'Signature non valide', 403

    # Signature valide, traiter la requête
    print("Webhook reçu :")
    print(request.json)  # Imprime les données JSON envoyées par WooCommerce
    
    # Répondre à WooCommerce pour indiquer que le webhook a été reçu avec succès
    return '', 200


