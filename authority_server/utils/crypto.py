import os
import rbcl
from cryptography.fernet import Fernet

class AuthorityCrypto:
    def __init__(self, private_key_bytes=None):
        """
        Initializes the Authority's cryptographic identity.
        """
        if private_key_bytes:
            self.private_key = private_key_bytes
            self.public_key = rbcl.crypto_scalarmult_ristretto255_base(self.private_key)
        else:
            # If no key was provided, we generate a fresh pair and store them as properties
            self._generate_and_set_keypair()

    def _generate_and_set_keypair(self):
        """
        Internal method (denoted by the underscore).
        Generates a new keypair and ties them directly to the object's properties.
        """
        self.private_key = rbcl.crypto_core_ristretto255_scalar_random()
        self.public_key = rbcl.crypto_scalarmult_ristretto255_base(self.private_key)

    def generate_nonce_commitment(self):
        k = rbcl.crypto_core_ristretto255_scalar_random()
        R = rbcl.crypto_scalarmult_ristretto255_base(k)
        return k, R

    def sign_blinded_challenge(self, blinded_challenge_bytes, k_bytes):
        try:
            c_times_x = rbcl.crypto_core_ristretto255_scalar_mul(blinded_challenge_bytes, self.private_key)
            s_prime = rbcl.crypto_core_ristretto255_scalar_add(k_bytes, c_times_x)
            return s_prime
        except Exception as e:
            # Vyhodíme obecnou chybu, že data nešlo zpracovat
            raise ValueError("Cryptographic operation failed: Invalid challenge format") from e

def get_cipher():
    ''' Returns master key from .env file. (This key must never be inside the database!)'''
    master_key = os.getenv("AUTHORITY_MASTER_KEY")
    if not master_key:
        raise ValueError("Master key is required and cannot be None.")
    
    return Fernet(master_key.encode())

def encrypt_private_key(raw_private_key_bytes: bytes) -> bytes:
    return get_cipher().encrypt(raw_private_key_bytes)

def decrypt_private_key(encrypted_private_key_bytes: bytes) -> bytes:
    # Přidáno bytes() pro konverzi případného memoryview z databáze
    return get_cipher().decrypt(bytes(encrypted_private_key_bytes))
    
if __name__ == "__main__":
    print("Initializing AuthorityCrypto without an existing key...")
    auth_crypto = AuthorityCrypto()
    
    # Let's check if the properties were successfully attached to the object
    has_priv = hasattr(auth_crypto, 'private_key')
    has_pub = hasattr(auth_crypto, 'public_key')
    
    print(f"Does the object have a private_key property? {has_priv}")
    print(f"Does the object have a public_key property? {has_pub}")
    
    if has_priv and has_pub:
        # We print them in hex format so they are readable in the terminal
        print(f"Private Key (hex): {auth_crypto.private_key.hex()}")
        print(f"Public Key (hex): {auth_crypto.public_key.hex()}")
        print("Success! Both keys are successfully bound to the object.")
    else:
        print("Error: Properties were not set correctly.")