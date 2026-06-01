# 🗳️ SecureVote - Anonymní Hlasovací Platforma

Tento projekt je maturitní prací zaměřenou na vývoj elektronického hlasovacího systému, který pomocí pokročilé kryptografie (Blind Signatures / Slepé podpisy na křivce Ristretto255) řeší základní paradox e-voleb: **zajišťuje naprostou anonymitu voličů při současném zachování ověřitelnosti a prevenci vícenásobného hlasování.**

Architektura je z bezpečnostních důvodů striktně rozdělena na dva oddělené servery, které spolu komunikují pouze asynchronně přes klienta.

---

## 📖 Uživatelská dokumentace

Systém se skládá z procesu vytvoření volby (Authority) a samotného hlasování (Voting).

### 1. Vytvoření nové ankety
1. Otevřete v prohlížeči Authority Server (standardně `http://127.0.0.1:5001/` nebo `https://domena.trycloudfare.com/create_voters`).
2. Vyplňte formulář: název ankety, možnosti (každou na nový řádek) a e-mailové adresy voličů.
3. Systém vygeneruje bezpečný kryptografický klíč a každému voliči odešle unikátní, jednorázový odkaz na e-mail.
4. Tvůrce ankety obdrží na svůj e-mail heslo pro administraci.

### 2. Průběh hlasování
1. Volič klikne na "Magic Link" ve svém e-mailu.
2. Po vybrání možnosti probíhá veškerá kryptografie (oslepení hlasu) přímo v jeho prohlížeči.
3. Hlas je bezpečně podepsán Authority Serverem (aniž by server viděl, pro koho volič hlasuje) a odeslán na Voting Server.
4. Po úspěšném vhození je jednorázový token nenávratně zničen (obrana proti Replay útokům).

### 3. Administrace a Archiv
- **Dashboard:** Na domovské stránce Voting serveru (`http://127.0.0.1:5002/` nebo `https://domena.trycloudfare.com`) klikněte na "Admin Login". Pomocí ID volby a hesla z e-mailu se přihlásíte do administrace, kde vidíte průběžnou volební účast a máte možnost volby předčasně ukončit.
- **Archiv:** Jakmile volbám vyprší čas (nebo jsou manuálně uzavřeny), výsledky se automaticky dešifrují a zveřejní v archivu na domovské stránce. Systém nepoužívá časově náročné Cron joby, ale efektivní "Ghost Admin" přístup (vyhodnocení expirace při dotazu).

---

## 💻 Vývojářská dokumentace

Tato sekce obsahuje návod na zprovoznění projektu ve vývojovém prostředí.

### 1. Prerekvizity
- **PostgreSQL:** Nainstalovaný a běžící databázový server.
- **Conda:** Pro správu Python prostředí.

### 2. Příprava databází
Z bezpečnostních důvodů musí mít každý server svou vlastní databázi. Spusťte v PostgreSQL rozhraní (např. pgAdmin nebo psql) následující příkazy:

```sql
-- Vytvoření databází
CREATE DATABASE authority_db;
CREATE DATABASE voting_db;

-- Vytvoření uživatelů
CREATE USER authority_user WITH ENCRYPTED PASSWORD 'auth_heslo';
CREATE USER voting_user WITH ENCRYPTED PASSWORD 'voting_heslo';

-- Přidělení práv
GRANT ALL PRIVILEGES ON DATABASE authority_db TO authority_user;
GRANT ALL PRIVILEGES ON DATABASE voting_db TO voting_user;
GRANT ALL ON SCHEMA public TO authority_user;
-- U PostgreSQL 15+ je nutné povolit public schema:
\c authority_db
GRANT ALL ON SCHEMA public TO authority_user;
\c voting_db
GRANT ALL ON SCHEMA public TO voting_user;
```

3. Nastavení Python prostředí

V kořenovém adresáři voting serveru se nachází soubor environment.yml. Nainstalujte a aktivujte prostředí:

    conda env create -f environment.yml
    conda activate maturita_projekt

4. Konfigurace prostředí (.env)

V každém adresáři serveru (authority_server a voting_server) vytvořte soubor .env.

Příklad pro Authority Server (.env):

    FLASK_SECRET_KEY=vas_tajny_klic
    HMAC_SECRET_KEY=tajny_klic_pro_tokeny
    AUTHORITY_MASTER_KEY=fernet_master_key_vygenerovany_z_cryptography
    VOTING_SERVER_URL=https://domena.trycloudflare.com 
    LOCAL_VOTING_SERVER=http://127.0.0.1:5002

    # Databáze
    DB_NAME=authority_db
    DB_USER=authority_user
    DB_PASSWORD=auth_heslo
    DB_HOST=localhost
    DB_PORT=5432

    # E-mail (SMTP)
    MAIL_USERNAME=tvuj_email@seznam.cz
    MAIL_PASSWORD=tvoje_heslo_nebo_app_pass
    SMTP_ADDRESS=smtp.seznam.cz
    SMTP_PORT=465

Příklad pro Voting Server (.env):


    FLASK_SECRET_KEY=vas_tajny_klic_2
    AUTHORITY_SERVER_URL=https://domena.trycloudflare.com
    
    # Databáze
    VOTING_DB_NAME=voting_db
    VOTING_DB_USER=voting_user
    VOTING_DB_PASSWORD=voting_heslo
    DB_HOST=localhost
    DB_PORT=5432

5. Nastavení domény
Pokud chcete spustit projekt na veřejné doméně, použijte Quick Tunnels od Cloudfared (zdarma).

Dle instrukcí na 
[Cloudflare quick tunnels instructions](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/)
instalujte cloudfared, a dle dalších instrukcí spusťte v příkazové řádce 2 quick tunnels - jeden na 127.0.0.1:5001 (authority server), druhý na 127.0.0.1:5002(voting_server), nepoužívejte localhost kvůli problémům s IPv4/IPv6.

Pak zkopírujte odkazy k oboum tunelům, odkaz na server Autority (port 5001) vložte do .env a client_crypto.js souborů v složce voting_server a odkaz na server Hlasovací (port 5002) vložte do .env souboru v složce authority_server.

6. Spuštění aplikace

Aplikace automaticky detekuje chybějící tabulky a sama si je pomocí pool managementu při startu vygeneruje.

    Spusťte Authority Server:

    cd authority_server
    python app.py


    Spusťte Voting Server:

    cd voting_server
    python app.py
