import psycopg2
import os
from psycopg2.extensions import connection
from psycopg2 import pool, extras
import json

class VotingDatabase:
    _connection_pool = None
    
    @classmethod
    def initialize_pool(cls):
        """Inicializuje pool, pokud ještě neexistuje. Volá se při startu aplikace."""
        if cls._connection_pool is None:
            print("Initializing database connection pool.")
            cls._connection_pool = pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                dbname=os.getenv("VOTING_DB_NAME", "voting_db"),
                user=os.getenv("VOTING_DB_USER", "voting_user"),
                password=os.getenv("VOTING_DB_PASSWORD", ""),
                host=os.getenv("DB_HOST", "localhost"),
                port=os.getenv("DB_PORT", "5432"),
            )
            
    def __init__(self):
        """
        Initializes the database connection using environment variables.
        """
        self.conn: connection | None = None

    
    def __enter__(self) -> 'VotingDatabase':
        if VotingDatabase._connection_pool is None:
            VotingDatabase.initialize_pool()
            
        if VotingDatabase._connection_pool is None:
            raise RuntimeError("Connection pool could not be initialized.")
        
        self.conn = VotingDatabase._connection_pool.getconn()
        
        if self.conn is None:
            raise RuntimeError("Pool was initialized but fetching a connection from it was unsuccessful.")
        self.conn.autocommit = True
        return self
    
    def __exit__(self, exc_type, exc_val, traceback):
        if self.conn and VotingDatabase._connection_pool is not None:
            if exc_type is not None:
                self.conn.rollback() 
            
            VotingDatabase._connection_pool.putconn(self.conn)
        
        # Pokud došlo k chybě, tyto proměnné nebudou prázdné
        if exc_type:
            print(f"Warning: Error occurred inside the block: {exc_val}, traceback: {traceback}")
            
    def setup_tables(self):
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with VotingDatabase() as db:'")
        
        with self.conn.cursor() as cur:
            cur.execute('''
            CREATE TABLE IF NOT EXISTS elections_voting (
                poll_id VARCHAR(255) PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                options JSONB NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                status VARCHAR(50) DEFAULT 'open',
                admin_password_hash VARCHAR(255) NOT NULL,
                allow_multiple BOOLEAN DEFAULT FALSE,
                public_key VARCHAR(64) NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS cast_votes (
                id SERIAL PRIMARY KEY,
                poll_id VARCHAR(255) REFERENCES elections_voting(poll_id) ON DELETE CASCADE,
                vote_data JSONB NOT NULL,
                r_prime_hex VARCHAR(64) NOT NULL,
                s_prime_hex VARCHAR(64) UNIQUE NOT NULL
            );
        
            CREATE INDEX IF NOT EXISTS idx_status ON elections_voting (status);
            CREATE INDEX IF NOT EXISTS idx_expires_at ON elections_voting (expires_at);
            ''')
            
    def store_election(self, poll_id, title, options, expires_at, admin_password_hash, public_key, allow_multiple):
        """
        Saves initialized poll into the database.
        """
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with VotingDatabase() as db:'")
        
        with self.conn.cursor() as cur:
            # Převedeme Python list na formátovaný JSON string pro sloupec JSONB
            options_json = json.dumps(options)
            
            # Bezpečný INSERT pomocí parametrizovaného dotazu (%s) proti SQL Injection
            cur.execute('''
                INSERT INTO elections_voting 
                (poll_id, title, options, expires_at, admin_password_hash, public_key, allow_multiple)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (poll_id, title, options_json, expires_at, admin_password_hash, public_key, allow_multiple))
    
    def get_active_poll(self, poll_id):
        """
        Získá data o hlasování. Pokud už vypršel čas, ale volba je ještě 'open',
        provede Ghost Admin úpravu (uloží ji jako 'closed') a odepře přístup.
        """
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with VotingDatabase() as db:'")
            
        with self.conn.cursor() as cur:
            # Vytáhneme data a necháme rovnou SQL vyhodnotit, zda už vypršel čas
            cur.execute('''
                SELECT title, options, status, public_key, allow_multiple, 
                       (expires_at < (NOW() AT TIME ZONE 'UTC')) as is_expired
                FROM elections_voting 
                WHERE poll_id = %s
            ''', (poll_id,))
            
            row = cur.fetchone()
            
            # volby vůbec neexistují
            if not row:
                return None
                
            title, options, status, public_key, allow_multiple, is_expired = row
            
            # volby už byly dříve oficiálně uzavřeny
            if status == 'closed':
                return None
                
            # GHOST ADMIN PATTERN: čas už vypršel, ale databáze má ještě status 'open'
            if is_expired:
                cur.execute("UPDATE elections_voting SET status = 'closed' WHERE poll_id = %s", (poll_id,))
                return None
                
            # volba běží
            return {
                "title": title,
                "options": options, #psycopg2 rovnou vrátí list díky JSONB
                "public_key": public_key,
                "allow_multiple": allow_multiple
            }
    def store_vote(self, poll_id, vote, R_prime_hex, s_prime_hex):
        '''Uloží k danému poll id samotný hlas společně s
        matematickým bodem a skalárem - R' a s',
        které slouží k případné pozdější kontrole hlasu.'''
        vote_data = json.dumps(vote)
    
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with VotingDatabase() as db:'")
            
        with self.conn.cursor() as cur:
            cur.execute('''
                INSERT INTO cast_votes
                (poll_id, vote_data, r_prime_hex, s_prime_hex)
                VALUES (%s, %s, %s, %s)
            ''', (poll_id, vote_data, R_prime_hex, s_prime_hex))
            
    def get_admin_data(self, poll_id):
        """Ověření hesla a statusu pro login administrátora."""
        if self.conn is None:
            raise RuntimeError("Database isn't connected.")
            
        with self.conn.cursor() as cur:
            cur.execute('''
                SELECT admin_password_hash, status 
                FROM elections_voting 
                WHERE poll_id = %s
            ''', (poll_id,))
            return cur.fetchone()

    def get_vote_results(self, poll_id):
        """Vrací celkový počet voličů a agregované výsledky přes CTE a LATERAL JOIN."""
        if self.conn is None:
            raise RuntimeError("Database isn't connected.")
            
        with self.conn.cursor() as cur:
            # Počet unikátních lístků (voličů)
            cur.execute("SELECT COUNT(id) FROM cast_votes WHERE poll_id = %s", (poll_id,))
            row = cur.fetchone()
            total_votes = row[0] if row else 0

            # Agregace hlasů vč. možností s 0 hlasy
            cur.execute('''
                WITH master_options AS (
                    SELECT jsonb_array_elements_text(options) AS opt_name
                    FROM elections_voting
                    WHERE poll_id = %s
                ),
                actual_votes AS (
                    SELECT opt_text, COUNT(*) as vote_count
                    FROM cast_votes, 
                    LATERAL jsonb_array_elements_text(vote_data) AS opt_text
                    WHERE poll_id = %s
                    GROUP BY opt_text
                )
                SELECT m.opt_name, COALESCE(v.vote_count, 0) as final_count
                FROM master_options m
                LEFT JOIN actual_votes v ON m.opt_name = v.opt_text
                ORDER BY final_count DESC;
            ''', (poll_id, poll_id))
            
            results_dict = dict(cur.fetchall())
            return total_votes, results_dict

    def close_poll_early(self, poll_id):
        """Předčasný kill-switch pro volby."""
        if self.conn is None:
            raise RuntimeError("Database isn't connected.")
            
        with self.conn.cursor() as cur:
            cur.execute("UPDATE elections_voting SET status = 'closed' WHERE poll_id = %s", (poll_id,))

    def get_dashboard_info(self, poll_id):
        """Sdružený dotaz pro dashboard vč. Ghost Admin patternu a public klíče."""
        if self.conn is None:
            raise RuntimeError("Database isn't connected.")
            
        with self.conn.cursor() as cur:
            cur.execute('''
                SELECT 
                    e.title, 
                    e.status, 
                    e.expires_at,
                    e.allow_multiple,
                    e.options, 
                    (e.expires_at < (NOW() AT TIME ZONE 'UTC')) as is_expired,
                    (SELECT COUNT(id) FROM cast_votes WHERE poll_id = %s) as total_votes,
                    e.public_key
                FROM elections_voting e
                WHERE e.poll_id = %s
            ''', (poll_id, poll_id))
            
            row = cur.fetchone()
            if not row:
                return None 

            title, status, expires_at, allow_multiple, options, is_expired, total_voters, public_key = row
            
            # Lazy vyhodnocení expirace (Ghost Admin)
            if status == 'open' and is_expired:
                cur.execute("UPDATE elections_voting SET status = 'closed' WHERE poll_id = %s", (poll_id,))
                status = 'closed'
            
            return {
                "title": title,
                "status": status,
                "expires_at": expires_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
                "allow_multiple": allow_multiple,
                "options": options,
                "total_votes": total_voters,
                "public_key": public_key
            }
    
    def auto_close_expired_polls(self):
        """Ghost Admin: Hromadně uzavře vše, co už mělo skončit."""
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with VotingDatabase() as db:'")
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE elections_voting 
                SET status = 'closed' 
                WHERE status = 'open' AND expires_at < (NOW() AT TIME ZONE 'UTC')
            """)

    def get_archived_polls(self, query=""):
        """Vrací uzavřené volby, volitelně filtrované podle názvu."""
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with VotingDatabase() as db:'")
        with self.conn.cursor() as cur:
            sql = """
                SELECT poll_id, title, expires_at, 
                (SELECT COUNT(*) FROM cast_votes WHERE poll_id = elections_voting.poll_id) as votes
                FROM elections_voting 
                WHERE status = 'closed'
            """
            params = []
            if query:
                sql += " AND title ILIKE %s"
                params.append(f"%{query}%")
            
            sql += " ORDER BY expires_at DESC LIMIT 20"
            
            cur.execute(sql, params)
            if cur.description is None:
                return []
            # Převedeme na seznam slovníků pro snadnou práci v Jinja2
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in cur.fetchall()]

    def get_raw_votes(self, poll_id):
        """Vrátí všechny odevzdané hlasy a podpisy, agregované přímo v databázi."""
        if self.conn is None:
            raise RuntimeError("Database isn't connected.")
            
        with self.conn.cursor() as cur:
            # json_build_object vytvoří slovník, json_agg je spojí do pole
            # COALESCE zajistí, že pokud nejsou žádné hlasy, vrátí se prázdné pole [] místo None
            cur.execute('''
                SELECT COALESCE(json_agg(
                    json_build_object(
                        'vote_data', vote_data,
                        'r_prime', r_prime_hex,
                        's_prime', s_prime_hex
                    )
                ), '[]'::json)
                FROM cast_votes 
                WHERE poll_id = %s
            ''', (poll_id,))
            
            row = cur.fetchone()
            
            if row is not None:
                return row[0]
            
            # fallback, pokud by se databáze zbláznila a nevrátila vůbec nic
            return []