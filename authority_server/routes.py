import secrets
import requests
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, render_template, jsonify
from database import AuthorityDatabase  
from utils.email_service import send_admin_email, send_voter_email
from utils.crypto import AuthorityCrypto, encrypt_private_key, decrypt_private_key
from werkzeug.security import generate_password_hash
import hmac
import hashlib
import os
from flask_cors import CORS
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

voting_url=os.getenv("VOTING_SERVER_URL", "192.168.1.55")
executor = ThreadPoolExecutor()
ip_last_setup = {}

@app.context_processor
def inject_urls():
    return dict(
        voting_url=os.getenv('VOTING_SERVER_URL', '#')
    )
    
def background_voter_processing(voter_emails, poll_id, title):
    with AuthorityDatabase() as db:
        
        if db.conn is None:
            print("CRITICAL ERROR: database connection unsuccessful. Email processing ended.")
            return
        
        secret_key_str = os.getenv("HMAC_SECRET_KEY")
        if secret_key_str is None:
            print("CRITICAL ERROR: no HMAC key present in .env file. Email processing ended.")
            return
        hmac_secret = secret_key_str.encode('utf-8')
        
        for email in voter_emails:
            # vytvoření zprávy, kterou chceme hašovat (spojíme email a poll_id)
            message = f"{email}:{poll_id}".encode('utf-8')
            
            # výpočet HMAC-SHA256 a převod na hexdigest (čistý textový string)
            voter_token = hmac.new(hmac_secret, message, hashlib.sha256).hexdigest()
            
            with db.conn.cursor() as cur:
                cur.execute('''
                    INSERT INTO voter_issuance (token, poll_id, status)
                    VALUES (%s, %s, 'registered')
                    ON CONFLICT DO NOTHING
                ''', (voter_token, poll_id))
                
            magic_link = f"{voting_url}/vote/{poll_id}?token={voter_token}"
            send_voter_email(email, title, magic_link)

@app.route('/create_voters', methods=['POST'])
def create_voters():
    #PARSE the input
    client_ip = request.remote_addr
    now = datetime.now()
    
    if client_ip in ip_last_setup:
        time_passed = now - ip_last_setup[client_ip]
        if time_passed < timedelta(minutes=1):
            return jsonify({"error": "Too many requests from your IP. Please wait 1 minute."}), 429
            
    # Pokud prošel, zapíšeme mu nový čas
    ip_last_setup[client_ip] = now
    
    title = request.form.get('title')
    creator_email = request.form.get('creator_email')
    expires_at = request.form.get('expires_at')
    allow_multiple_str = request.form.get("allow_multiple")
    allow_multiple = True if allow_multiple_str == "true" else False
    
    options = [line.strip() for line in request.form.get('options', '').split('\n') if line.strip()]
    voter_emails = [line.strip() for line in request.form.get('voters', '').split('\n') if line.strip()]
    
    admin_password = secrets.token_hex(8)
    admin_password_hash = generate_password_hash(admin_password)
    
    auth_crypto = AuthorityCrypto()
    raw_private_key = auth_crypto.private_key
    public_key_hex = auth_crypto.public_key.hex()
    
    encrypted_private_key = encrypt_private_key(raw_private_key)
    
    local_voting_server_url = os.getenv('LOCAL_VOTING_SERVER', '127.0.0.1:5002')
    election_data = {
        "title": title,
        "options": options,
        "expires_at": expires_at,
        "admin_password_hash": admin_password_hash,
        "authority_public_key": public_key_hex,
        "allow_multiple": allow_multiple
    }
    
    try:
        response = requests.post(f"{local_voting_server_url}/setup_election", json=election_data)
        if response.status_code != 200:
            return f"Error: Voting server denied the configuration.", 500
        
        poll_id = response.json().get("poll_id")
    except Exception as e:
        return f"Error: Unsuccessful connection to voting server: {e}", 500
    
    # Uložení voleb a klíče do Authority DB
    with AuthorityDatabase() as db:
        if db.conn is None:
            print("Critical Error: database connection unsuccessful.")
            return "Database connection failed", 500
        with db.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO elections_auth (poll_id, encrypted_priv_key) VALUES (%s, %s)", 
                (poll_id, encrypted_private_key)
            )
    
    executor.submit(send_admin_email, creator_email, title, poll_id, admin_password)
    executor.submit(background_voter_processing, voter_emails, poll_id, title)
    
    return render_template('success.html')

@app.route('/get_commitment', methods=['POST'])
def get_commitment():
    data = request.json
    if not data:
        print("ERROR: no data obtained with which to verify user and generate commitment.")
        return jsonify({"error": "Missing JSON data"}), 400
    
    token = data.get('token')
    poll_id = data.get('poll_id')
    
    if not token or not poll_id:
         return jsonify({"error": "Missing token or poll_id"}), 400
     
    with AuthorityDatabase() as db:
        if not db.is_voter_eligible(token):
            return jsonify({"error": "Unauthorized or already voted"}), 403
        
        encrypted_key = db.get_private_key(poll_id)
        if not encrypted_key:
            return jsonify({"error": "Election not found"}), 404
        
        raw_key = decrypt_private_key(encrypted_key)
        
        auth_crypto = AuthorityCrypto(raw_key)
        k_bytes, R_bytes = auth_crypto.generate_nonce_commitment()
        
        db.store_voter_nonce(token, k_bytes)
        
    return jsonify({"R": R_bytes.hex()}), 200

@app.route('/issue_signature', methods=['POST'])
def issue_signature():
    data = request.json
    if not data:
        print("ERROR: no data obtained with which to verify user and generate commitment.")
        return jsonify({"error": "Missing JSON data"}), 400
    
    token = data.get('token')
    poll_id = data.get('poll_id')
    blinded_challenge_hex = data.get('blinded_challenge')
    
    if not token or not poll_id or not blinded_challenge_hex:
         return jsonify({"error": "Missing token, poll_id or blinded challenge"}), 400
    # c_bytes is the blinded challenge in byte format, the name c stems from the blind Schnorr mathematical formula (denotes challenge)
    try:
        c_bytes = bytes.fromhex(blinded_challenge_hex)
    except ValueError:
        return jsonify({"error": "Invalid blinded challenge format"}), 400
    
    with AuthorityDatabase() as db:
        k_bytes = db.fetch_and_delete_voter_nonce(token)
        
        if not k_bytes:
            return jsonify({"error": "Nonce not found or already used."}), 403
        
        encrypted_key = db.get_private_key(poll_id)
        if not encrypted_key:
            return jsonify({"error": "Election not found"}), 404
        
        raw_key = decrypt_private_key(encrypted_key)
        
        auth_crypto = AuthorityCrypto(raw_key)
        try:
            blind_signature = auth_crypto.sign_blinded_challenge(c_bytes, k_bytes)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        
        db.mark_signature_issued(token)
    return jsonify({"blind_signature": blind_signature.hex()}), 200

@app.route('/')
def index():
    return render_template('create.html')