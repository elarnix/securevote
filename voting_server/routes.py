import uuid
from flask import request, jsonify, Flask, render_template, session, flash, redirect, url_for, send_file, Response
from database import VotingDatabase
import psycopg2
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import rbcl
import json
import hashlib
from werkzeug.security import check_password_hash
import csv
import os
import io

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'nahodny-string-pro-vyvoj')

@app.context_processor
def inject_poll_id():
    # Tento kód zajistí, že v KAŽDÉ šabloně bude dostupná proměnná active_poll_id
    return dict(
        active_poll_id=session.get('current_poll_id'),
        authority_url=os.getenv('AUTHORITY_SERVER_URL', '#')
        )

@app.route('/setup_election', methods=['POST'])
def setup_election():
    if not request.json:
        print("Request error during setup_election: Missing JSON payload")
        return jsonify({"error": "Missing JSON payload"}), 400
    
    data = request.json
    title = data.get('title')
    options = data.get('options')
    expires_at_raw = data.get('expires_at')
    admin_password_hash = data.get('admin_password_hash')
    authority_public_key = data.get('authority_public_key')
    # default value False in .get(), because it's a boolean
    allow_multiple = data.get('allow_multiple', False) 
    try:
        # Očekáváme přesný formát z frontend/Authority (např. "2024-12-31T23:59")
        local_dt = datetime.strptime(expires_at_raw, '%Y-%m-%dT%H:%M')
    except ValueError:
        print(f"Formating error: Invalid date format received: {expires_at_raw}")
        return jsonify({"error": "Invalid expires_at format. Expected YYYY-MM-DDTHH:MM"}), 400
    except TypeError:
         # Pokud expires_at_raw chybí úplně a je None
         return jsonify({"error": "Missing expires_at parameter."}), 400
    local_dt = local_dt.replace(tzinfo=ZoneInfo("Europe/Prague"))
    utc_dt = local_dt.astimezone(timezone.utc)
    expires_at = utc_dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # kontrola přijatých dat
    if not title or not options or not expires_at or not admin_password_hash or not authority_public_key:
        return jsonify({"error": "Missing required fields in payload"}), 400
      
    # uložení do Voting databáze (s využitím vygenerovaného poll_id)
    max_retries = 3
    poll_id = None

    for attempt in range(max_retries):
        current_id = uuid.uuid4().hex
        try:
            with VotingDatabase() as db:
                db.store_election(
                    poll_id=current_id,
                    title=title,
                    options=options,
                    expires_at=expires_at,
                    admin_password_hash=admin_password_hash,
                    public_key=authority_public_key,
                    allow_multiple=allow_multiple
                )
            poll_id = current_id
            break 
            
        except psycopg2.errors.UniqueViolation:
            # pokud nastala kolize PK (poll_id), logujeme a zkusíme další iteraci
            print(f"Collision detected for poll_id: {current_id}. Retrying...")
            continue 
            
        except Exception as e:
            # Ostatní chyby (např. pád DB) nechceme zkoušet znovu
            print(f"Critical database error: {e}")
            return jsonify({"error": "Database error"}), 500
    
    # Pokud se ani po 3 pokusech nepodařilo (teoreticky nemožné s UUID)
    if not poll_id:
        return jsonify({"error": "Failed to generate unique poll ID"}), 500

    return jsonify({"poll_id": poll_id}), 200

@app.route('/vote/<poll_id>', methods=['GET'])
def view_ballot(poll_id):
    # 2. Token vytáhni z request.args (to je to, co je v URL za ?token=)
    token = request.args.get('token')
    # 2. Kontrola: Pokud token v URL chybí, vrať chybu (např. 400)
    if not token:
        return jsonify({"error": "Request error, missing token"}), 400
    # 3. Zavolej naši novou metodu z databáze: 
    try:
        with VotingDatabase() as db:
            election_data = db.get_active_poll(poll_id)
        
            if election_data is None: #volby neexistují nebo již vypršely
                return render_template('error.html', message="Volba již skončila nebo neexistuje.")
            # pokud data jsou, pošli je do šablony jinja2
            return render_template('ballot.html', 
                                 election=election_data, 
                                 token=token, 
                                 poll_id=poll_id)
    except Exception as e:
        print(f"Critical error in view_ballot: {e}")
        return "Interní chyba serveru", 500

@app.route('/thank_you', methods=['GET'])
def load_thank_you_page():
   return render_template('thank_you.html')

@app.route('/cast_vote', methods=['POST'])
def cast_vote():
    # 1. ZÍSKÁNÍ DAT
    if not request.json:
        print("Request error during cast_vote: Missing JSON payload")
        return jsonify({"error": "Missing JSON payload"}), 400
    
    data = request.json
    poll_id = data.get('poll_id')
    vote = data.get('vote')
    R_prime_hex = data.get('R_prime')
    s_prime_hex = data.get('s_prime')
    
    # Bezpečné ověření - list má vždy 4 prvky (případně naplněné None)
    if not all([poll_id, vote, R_prime_hex, s_prime_hex]):
        return jsonify({"error": "Missing required fields in payload"}), 400

    # 2. VYZVEDNUTÍ KLÍČE
    with VotingDatabase() as db:
        poll = db.get_active_poll(poll_id) 
        
        if poll is None:
            return jsonify({'error': 'Poll is either not found or already closed.'}), 404
            
        public_key = poll['public_key']
        
    # 3. KRYPTOGRAFICKÁ PŘÍPRAVA A OVĚŘENÍ
    try:   
        Y_bytes = bytes.fromhex(public_key)
        R_prime_bytes = bytes.fromhex(R_prime_hex)
        s_prime_bytes = bytes.fromhex(s_prime_hex)
        
        if isinstance(vote, list): 
            vote = sorted(vote)
            vote_string = ";".join(vote) # Spojíme středníkem, přesně jako v JS
        else:
            vote_string = str(vote) # Pro jistotu, kdyby přišel jen string
            
        vote_bytes = vote_string.encode('utf-8')
        combined_bytes = R_prime_bytes + vote_bytes
        
        hash_bytes = hashlib.blake2b(combined_bytes, digest_size=64).digest()
        c_prime = rbcl.crypto_core_ristretto255_scalar_reduce(hash_bytes)
        
        s_G = rbcl.crypto_scalarmult_ristretto255_base(s_prime_bytes)
        c_Y = rbcl.crypto_scalarmult_ristretto255(c_prime, Y_bytes)
        
        L = s_G
        P = rbcl.crypto_core_ristretto255_add(R_prime_bytes, c_Y)
        
        if L != P:
            print('Cryptography check failed, invalid signature!')
            return jsonify({'error': 'Cryptography check failed, invalid signature!'}), 403
            
    except ValueError as e:
        print(f"Data formatting error: {e}")
        return jsonify({'error': 'Invalid data format provided.'}), 400
    except Exception as e:
        print(f"Cryptography error: {e}")
        return jsonify({'error': 'Internal server error during verification.'}), 500

    # 4. ULOŽENÍ DO DATABÁZE
    try:
        with VotingDatabase() as db:
            db.store_vote(poll_id, vote, R_prime_hex, s_prime_hex)
            
        return jsonify({'message': 'Vote successfully cast!'}), 200
        
    except psycopg2.errors.UniqueViolation:
        # ZACHYCENÍ REPLAY ÚTOKU!
        print("Replay attack detected: Signature already used.")
        return jsonify({'error': 'This exact ballot has already been cast!'}), 403
    except Exception as e:
        print(f"Database error during vote storage: {e}")
        return jsonify({'error': 'Internal database error.'}), 500
    
@app.route('/admin', methods=['GET', 'POST'])
@app.route('/admin/<poll_id>', methods=['GET', 'POST'])
def admin_login(poll_id=None):
    if poll_id and session.get('admin_for') == poll_id:
        return redirect(url_for('admin_dashboard', poll_id=poll_id))
    
    if request.method == 'POST':
        form_poll_id = request.form.get('poll_id') or poll_id
        password = request.form.get('password')
        
        if not form_poll_id or not password:
            flash('Missing poll ID or password.', 'error')
            return redirect(url_for('admin_login', poll_id=form_poll_id or poll_id))
        
        with VotingDatabase() as db:
            admin_data = db.get_admin_data(form_poll_id)
            
        if not admin_data:
            flash('Poll with this ID not found.', 'error')
            return redirect(url_for('admin_login'))
            
        pass_hash = admin_data[0]
        
        if check_password_hash(pass_hash, password):
            session['admin_for'] = form_poll_id
            return redirect(url_for('admin_dashboard', poll_id=form_poll_id))
        else:
            flash('Incorrect password, please try again.', 'error')
            return redirect(url_for('admin_login', poll_id=form_poll_id))
        
    poll_id_from_url = request.args.get('poll_id', '')
    
    return render_template('admin_login.html', poll_id=poll_id_from_url)


@app.route('/admin/<poll_id>/dashboard')
def admin_dashboard(poll_id):
    # 1. Autorizace
    if session.get('admin_for') != poll_id:
        flash("Unauthorized access. Please log in first.", "error")
        return redirect(url_for('admin_login', poll_id=poll_id))
    
    with VotingDatabase() as db:
        poll_info = db.get_dashboard_info(poll_id)
        
    # 2. Validace existence
    if not poll_info:
        session.pop('current_poll_id', None) # Vyčistíme navigaci, pokud poll neexistuje
        flash("Poll not found.", "error")
        return redirect(url_for('admin_login'))
    
    # 3. Nastavení navigace (kotva)
    session['current_poll_id'] = poll_id
    
    # 4. Rozhodnutí o zobrazení (Logic belongs here!)
    if poll_info['status'] == 'open':
        return render_template('admin_dashboard.html', poll=poll_info, poll_id=poll_id)
    
    # Pokud jsou volby closed, dashboard už není potřeba, ukaž výsledky
    return redirect(url_for('public_results', poll_id=poll_id))


@app.route('/admin/<poll_id>/close', methods=['POST'])
def admin_close(poll_id):
    # Ochrana (vyhazujeme na login!)
    if session.get('admin_for') != poll_id:
        flash("Unauthorized access. Please log in first.", "error")
        return redirect(url_for('admin_login', poll_id=poll_id))
        
    with VotingDatabase() as db:
        db.close_poll_early(poll_id)
    
    flash('Poll was successfully closed.', 'success')
    return redirect(url_for('public_results', poll_id=poll_id))


@app.route('/results/<poll_id>')
def public_results(poll_id):
    with VotingDatabase() as db:
        poll_info = db.get_dashboard_info(poll_id)
        
        if not poll_info:
            flash("Poll not found.", "error")
            return redirect(url_for('admin_login'))

        # Ochrana: Výsledky jsou tajné, dokud volby běží
        if poll_info['status'] == 'open':
            flash("This election is still running. Results are hidden.", "info")
            return redirect(url_for('index'))

        # Databáze vrací data už kompletní, včetně nulových hodnot a správně seřazená
        total_votes, db_results = db.get_vote_results(poll_id)

        # Výpočet procent (jediná věc, kterou děláme v Pythonu)
        final_results = []
        for option_name, votes_count in db_results.items():
            percent = round((votes_count / total_votes) * 100, 1) if total_votes > 0 else 0
                
            final_results.append({
                "label": option_name,
                "votes": votes_count,
                "percent": percent
            })

        return render_template('results.html', 
                               poll_info=poll_info, 
                               final_results=final_results, 
                               poll_id=poll_id)
        
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/')
def index():
    search_query = request.args.get('q', '').strip()
    
    with VotingDatabase() as db:
        # provedeme hromadný Ghost Admin Close pro všechny expirované volby
        #-> v archivu se objeví i ty, na které nikdo dlouho neklikl
        db.auto_close_expired_polls()
        
        # získáme seznam uzavřených voleb (podpora vyhledávání)
        archived_polls = db.get_archived_polls(search_query)
        
    return render_template('index.html', polls=archived_polls, search_query=search_query)

# Pomocná routa pro odhlášení z admin sekce
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_for', None)
    session.pop('current_poll_id', None)
    flash("Admin session ended.", "info")
    return redirect(url_for('index'))

@app.route('/results/<poll_id>/csv')
def download_results_csv(poll_id):
    with VotingDatabase() as db:
        poll_info = db.get_dashboard_info(poll_id)
        total_votes, db_results = db.get_vote_results(poll_id) # Tvoje skutečná metoda!
    
    if not poll_info:
        return "Poll not found", 404
        
    output = io.StringIO()
    # Středník je pro český Excel
    writer = csv.writer(output, delimiter=';')
    
    # Hlavička
    writer.writerow(['Poll title:', poll_info['title']])
    writer.writerow(['Total votes:', total_votes])
    writer.writerow([]) # Prázdný řádek
    
    writer.writerow(['Option', 'Vote amount'])
    for option, count in db_results.items():
        writer.writerow([option, count])
    
    # díky utf-8-sig Excel přečte správně českou diakritiku
    response = Response(
        output.getvalue().encode('utf-8-sig'),
        mimetype="text/csv"
    )
    response.headers["Content-Disposition"] = f"attachment; filename=results_{poll_id}.csv"
    return response

@app.route('/results/<poll_id>/verify')
def download_verification_data(poll_id):
    with VotingDatabase() as db:
        poll_info = db.get_dashboard_info(poll_id)
        raw_votes = db.get_raw_votes(poll_id) 
    
    if not poll_info:
        return "Poll not found", 404
        
    # převedeme na hezký JSON s veřejným klíčem a kontrolní rovnicí!
    verification_data = {
        "poll_id": poll_id,
        "poll_title": poll_info['title'],
        "authority_public_key": poll_info['public_key'],
        "description": (
            "This file contains anonymized votes and their cryptographic signatures. "
            "To verify the integrity of any vote, use the Authority Public Key (Y) and verify that L == P, where: "
            "1) c' = Hash(R' || vote_data) "
            "2) L = s' * G "
            "3) P = R' + (c' * Y). "
            "All operations are performed over the Ristretto255 elliptic curve."
        ),
        "votes": raw_votes
    }
    
    return Response(
        json.dumps(verification_data, indent=4),
        mimetype="application/json",
        headers={"Content-disposition": f"attachment; filename=verify_election_{poll_id}.json"}
    )
    