from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
import json
import logging
import traceback

logger = logging.getLogger(__name__)

class CryptoManager:
    @staticmethod
    def generate_key_pair():
        """Generate a new RSA key pair"""
        try:
            key = RSA.generate(2048)
            private_key = key.export_key(format='PEM')
            public_key = key.publickey().export_key(format='PEM')
            
            # Log the generated key formats
            logger.debug(f"Generated private key format: {private_key[:64]}...")
            logger.debug(f"Generated public key format: {public_key[:64]}...")
            
            return private_key, public_key
        except Exception as e:
            logger.error(f"Key generation error: {str(e)}")
            logger.error(f"Stack trace: {traceback.format_exc()}")
            raise

    @staticmethod
    def encrypt_data(data, public_key):
        """Encrypt data using hybrid encryption (RSA + AES)"""
        try:
            # Log key format for debugging
            logger.debug(f"Public key type: {type(public_key)}")
            logger.debug(f"Public key format: {public_key[:64]}...")  # Show first 64 chars
            
            # Convert data to JSON string
            data_str = json.dumps(data)
            
            # Generate a random session key
            session_key = get_random_bytes(16)
            
            # Ensure public key is in bytes format
            if isinstance(public_key, str):
                if '-----BEGIN PUBLIC KEY-----' not in public_key:
                    public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
                public_key = public_key.encode()
            
            # Import the public key properly
            try:
                rsa_key = RSA.import_key(public_key)
                logger.debug("RSA key imported successfully")
            except ValueError as e:
                logger.error(f"Error importing RSA key: {str(e)}")
                raise
            
            # Encrypt the session key with RSA
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            enc_session_key = cipher_rsa.encrypt(session_key)
            
            # Encrypt the data with the session key
            cipher_aes = AES.new(session_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data_str.encode())
            
            # Return encrypted data components
            encrypted_data = {
                'enc_session_key': b64encode(enc_session_key).decode('utf-8'),
                'nonce': b64encode(cipher_aes.nonce).decode('utf-8'),
                'tag': b64encode(tag).decode('utf-8'),
                'ciphertext': b64encode(ciphertext).decode('utf-8')
            }
            return encrypted_data
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            logger.error(f"Stack trace: {traceback.format_exc()}")
            raise

    @staticmethod
    def decrypt_data(encrypted_data, private_key):
        """Decrypt data using hybrid encryption"""
        try:
            # Log key format for debugging
            logger.debug(f"Private key type: {type(private_key)}")
            logger.debug(f"Private key format: {private_key[:64]}...")  # Show first 64 chars
            
            # Decode components
            enc_session_key = b64decode(encrypted_data['enc_session_key'])
            nonce = b64decode(encrypted_data['nonce'])
            tag = b64decode(encrypted_data['tag'])
            ciphertext = b64decode(encrypted_data['ciphertext'])
            
            # Ensure private key is in bytes format
            if isinstance(private_key, str):
                if '-----BEGIN RSA PRIVATE KEY-----' not in private_key:
                    private_key = f"-----BEGIN RSA PRIVATE KEY-----\n{private_key}\n-----END RSA PRIVATE KEY-----"
                private_key = private_key.encode()
            
            # Import the RSA key properly
            try:
                rsa_key = RSA.import_key(private_key)
                logger.debug("RSA key imported successfully")
            except ValueError as e:
                logger.error(f"Error importing RSA key: {str(e)}")
                raise
            
            # Decrypt the session key
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
            
            # Decrypt the data
            cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
            
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            logger.error(f"Stack trace: {traceback.format_exc()}")
            raise

    @staticmethod
    def sign_data(data, private_key):
        """Sign data using RSA private key"""
        try:
            from Crypto.Signature import pkcs1_15
            
            # Log key format for debugging
            logger.debug(f"Private key type for signing: {type(private_key)}")
            logger.debug(f"Private key format for signing: {private_key[:64]}...")  # Show first 64 chars
            
            # Convert data to string and hash it
            data_str = json.dumps(data, sort_keys=True)
            h = SHA256.new(data_str.encode())
            
            # Ensure private key is in bytes format
            if isinstance(private_key, str):
                if '-----BEGIN RSA PRIVATE KEY-----' not in private_key:
                    private_key = f"-----BEGIN RSA PRIVATE KEY-----\n{private_key}\n-----END RSA PRIVATE KEY-----"
                private_key = private_key.encode()
            
            # Import the key properly
            try:
                key = RSA.import_key(private_key)
                logger.debug("RSA key imported successfully for signing")
            except ValueError as e:
                logger.error(f"Error importing RSA key for signing: {str(e)}")
                raise
            
            # Create signature
            signature = pkcs1_15.new(key).sign(h)
            return b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"Signing error: {str(e)}")
            logger.error(f"Stack trace: {traceback.format_exc()}")
            raise

    @staticmethod
    def verify_signature(data, signature, public_key):
        """Verify signature using RSA public key"""
        try:
            from Crypto.Signature import pkcs1_15
            
            # Import the key properly
            key = RSA.import_key(public_key)
            
            # Verify signature
            data_str = json.dumps(data, sort_keys=True)
            h = SHA256.new(data_str.encode())
            pkcs1_15.new(key).verify(h, b64decode(signature))
            return True
        except (ValueError, TypeError) as e:
            logger.error(f"Signature verification error: {str(e)}")
            return False
