from dotenv import load_dotenv
# načtení .env
load_dotenv(override=True)
from routes import app
from database import AuthorityDatabase

def initialize_system():
    print("Initializing Authority Server...")
    try:
        with AuthorityDatabase() as db:
            db.setup_tables()
        print("Database checked/created successfuly.")
    except Exception as e:
        print(f"Critical error while initializing database: {e}")
        exit(1)

if __name__ == '__main__':
    initialize_system()
    # authority server na portu 5001
    app.run(host='0.0.0.0', port=5001, debug=True)