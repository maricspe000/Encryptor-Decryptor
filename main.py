import cryptography
choice = input("Key from file,typed,  generated(or decrypt): ")

from cryptography.fernet import Fernet
if choice == "generated":
  x = input("Message to Encrypt: ")
  key = Fernet.generate_key()
  file = open('key.key', 'wb')
  file.write(key) # The key is type bytes still
  file.close()
  from cryptography.fernet import Fernet
  message = x.encode()

  f = Fernet(key)
  encrypted = f.encrypt(message)
  print("encrypted to enc.txt")
  file = open("enc.txt", "wb")
  file.write(encrypted)
  file.close()
elif choice == "typed":
  x = input("Message to Encrypt: ")
  import base64
  import os
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

  password_provided = input("Key: ") # This is input in the form of a string
  password = password_provided.encode() # Convert to type bytes
  salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
  )
  key = base64.urlsafe_b64encode(kdf.derive(password))
  print("Key Written!")
  file = open("key.key", "wb")
  file.write(key)
  file.close()
  from cryptography.fernet import Fernet
  message = x.encode()

  f = Fernet(key)
  encrypted = f.encrypt(message)
  print("encrypted to enc.txt")
  file = open("enc.txt", "wb")
  file.write(encrypted)
  file.close()


elif choice == "file":
  x = input("Message to Encrypt: ")
  file = open('key.key', 'rb')
  key = file.read() # The key will be type bytes
  file.close()

  from cryptography.fernet import Fernet
  message = x.encode()

  f = Fernet(key)
  encrypted = f.encrypt(message)
  print("encrypted to enc.txt")
  file = open("enc.txt", "wb")
  file.write(encrypted)
  file.close()
elif choice == 'decrypt':
  file = open('key.key', 'rb')
  key = file.read() # The key will be type bytes
  file.close()
  file = open('enc.txt', 'rb')
  encrypted = file.read() # The key will be type bytes
  file.close()  
  

  f = Fernet(key)
  decrypted = f.decrypt(encrypted)
  print("decrypted to dcr.txt" )
  file = open('dcr.txt', 'wb')
  file.write(decrypted) # The key is type bytes still
  file.close()
  






