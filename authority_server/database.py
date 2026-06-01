import os
from psycopg2.extensions import connection
from psycopg2 import pool

class AuthorityDatabase:
    _connection_pool = None
    
    @classmethod
    def initialize_pool(cls):
        """Inicializuje pool, pokud ještě neexistuje. Volá se při startu aplikace."""
        if cls._connection_pool is None:
            print("Initializing Authority database connection pool.")
            cls._connection_pool = pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                dbname=os.getenv("DB_NAME", "authority_db"),
                user=os.getenv("DB_USER", "authority_user"),
                password=os.getenv("DB_PASSWORD", ""),
                host=os.getenv("DB_HOST", "localhost"),
                port=os.getenv("DB_PORT", "5432")
            )
            
    def __init__(self):
        """Initializes the database connection using environment variables."""
        self.conn: connection | None = None

    def __enter__(self) -> 'AuthorityDatabase':
        if AuthorityDatabase._connection_pool is None:
            AuthorityDatabase.initialize_pool()
            
        if AuthorityDatabase._connection_pool is None:
            raise RuntimeError("Connection pool could not be initialized.")
            
        # Správné vyzvednutí spojení z Authority poolu
        self.conn = AuthorityDatabase._connection_pool.getconn()
        if self.conn is None:
            raise RuntimeError("Connection with database could not be made.")
        # Authority server doteď běžel na autocommitu, tak ho zachováme
        self.conn.autocommit = True 
        return self

    def __exit__(self, exc_type, exc_val, traceback):
        # Ochrana: vracíme spojení zpět do SPRÁVNÉHO poolu
        if self.conn and AuthorityDatabase._connection_pool is not None:
            if exc_type is not None and not self.conn.autocommit:
                self.conn.rollback() 
            
            AuthorityDatabase._connection_pool.putconn(self.conn)
            
    def setup_tables(self):
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with AuthorityDatabase() as db:'")
        
        with self.conn.cursor() as cur:
            # tabulka pro nonces (k)
            cur.execute('''
                CREATE TABLE IF NOT EXISTS elections_auth (
                    poll_id VARCHAR(50) PRIMARY KEY,
                    encrypted_priv_key BYTEA NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS voter_issuance(
                    token VARCHAR(64) NOT NULL,
                    poll_id VARCHAR(50) NOT NULL,
                    status VARCHAR(50) DEFAULT 'registered',
                    nonce_k BYTEA,
                    
                    PRIMARY KEY (poll_id, token),
                    FOREIGN KEY (poll_id) REFERENCES elections_auth(poll_id) ON DELETE CASCADE
                );
            ''')
            
    def store_voter_nonce(self, voter_token, k_bytes):
        """
        Stores the generated 'k' (nonce) for a specific voter.
        """
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with AuthorityDatabase() as db:'")
        
        with self.conn.cursor() as cur:
            cur.execute('''UPDATE voter_issuance SET nonce_k = %s WHERE token = %s;
                        ''', (k_bytes, voter_token)) 
            
            
    def is_voter_eligible(self, voter_token):
        """
        Zkontroluje, zda token existuje v databázi povolených voličů
        a zda mu ještě nebyl vydán podpis.
        """
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with AuthorityDatabase() as db:'")
        
        with self.conn.cursor() as cur:
            cur.execute('''
                SELECT status FROM voter_issuance WHERE token = %s;
            ''', (voter_token,))
            
            result = cur.fetchone()
            
            # nejdřív zkontrolujeme, že result není None, a pak vezmeme nultý prvek
            if result and result[0] == 'registered':
                return True
                
            return False
    def fetch_and_delete_voter_nonce(self, voter_token):
        """
        Vyzvedne nonce_k a následně ho smaže z databáze (ochrana proti Replay útokům).
        """
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with AuthorityDatabase() as db:'")
        
        with self.conn.cursor() as cur:
            # 1. Přečteme si starou hodnotu (před jejím smazáním)
            cur.execute("SELECT nonce_k FROM voter_issuance WHERE token = %s;", (voter_token,))
            result = cur.fetchone()
            
            # Pokud token neexistuje, nebo už je nonce smazaná, vrátíme None
            if not result or result[0] is None:
                return None
                
            # rovnou to převedeme z databázového memoryview na čisté Python bytes, 
            nonce_k_bytes = bytes(result[0]) 
            
            # 2. Okamžitě hodnotu smažeme (token je tím znehodnocen / spálen)
            cur.execute("UPDATE voter_issuance SET nonce_k = NULL WHERE token = %s;", (voter_token,))
            
            return nonce_k_bytes
        
    def mark_signature_issued(self, voter_token):
        """
        Permanently marks the token as signed, so that he can never never get another signature.
        """
        if self.conn is None:
            raise RuntimeError("Database isn't connected. Use the block 'with AuthorityDatabase() as db:'")
        
        with self.conn.cursor() as cur:
            cur.execute('''UPDATE voter_issuance SET status = 'credential_issued' WHERE token = %s;
            ''', (voter_token,))
    
    def get_private_key(self, poll_id):
        """Returns encrypted private key for a given poll from the table elections_auth."""
        if self.conn is None:
            raise RuntimeError("Database connection unsuccessful.")
            
        with self.conn.cursor() as cur:
            cur.execute("SELECT encrypted_priv_key FROM elections_auth WHERE poll_id = %s;", (poll_id,))
            result = cur.fetchone()
            return result[0] if result else None
        