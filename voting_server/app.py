from dotenv import load_dotenv
# načtení .env
load_dotenv(override=True)
from routes import app
from database import VotingDatabase

def initialize_system():
    print("Initializing Voting Server...")
    try:
        with VotingDatabase() as db:
            db.setup_tables()
        print("Voting Database checked/created successfully.")
    except Exception as e:
        print(f"Critical error while initializing database: {e}")
        exit(1)

if __name__ == '__main__':
    initialize_system()
    # voting server na portu 5002
    app.run(host='0.0.0.0', port=5002, debug=True)