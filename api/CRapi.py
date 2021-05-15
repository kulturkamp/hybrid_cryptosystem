from cryptography.RSA import RSA, oaep_unpad
from cryptography.AES import AES, get_iv
from cryptography.sha256 import sha256
import sys
import os


def list_to_bytes(lst):
    srt = ','.join(str(num) for num in lst)
    return srt.encode('utf-8')


def bytes_to_list(bts):
    srt = bts.decode('utf-8')
    return [int(s) for s in srt.split(',')]


def create_envelope(sender_name, receiver_public_key_file, session_key, filename):
    aes_obj = AES(session_key)
    iv = get_iv()
    output_file = aes_obj.encrypt_file(inputf=filename, iv=iv)

    path = os.path.join(sys.path[1] + '\\users\\', sender_name)
    sender_rsa_cfg = os.path.join(path, sender_name + '.rsa')
    rsa_obj = RSA(file=sender_rsa_cfg)
    with open(receiver_public_key_file, 'r') as pkey_file:
        raw_key = pkey_file.read().rstrip('\n').replace(' ', '')[1:-1].split(',')
    receiver_public_key = (int(raw_key[0]), int(raw_key[1]))
    encrypted_session_key = rsa_obj.oaep_encrypt(session_key, 512, 512, receiver_public_key)

    with open(filename, 'rb') as f:
        sha256_obj = sha256(f.read())
        file_hash = sha256_obj.hash()
    encrypted_hash = rsa_obj.oaep_encrypt(file_hash, 512, 512, rsa_obj.private_key)

    envelope_filename = sender_name + '.nvp'
    with open(os.path.join(path, envelope_filename), 'wb') as envelope:
        with open(output_file, 'rb') as f:
            envelope.write(list_to_bytes(encrypted_hash) + b'\n')
            envelope.write(list_to_bytes(encrypted_session_key) + b'\n')
            envelope.write(f.read())


def open_envelope(receiver_name, sender_public_key_path, envelope_path):
    with open(envelope_path, 'rb') as envelope:
        encrypted_hash = bytes_to_list(envelope.readline())
        encrypted_session_key = bytes_to_list(envelope.readline())
        encrypted_file_lines = envelope.read()

    envelope_file_name = os.path.basename(envelope_path)
    with open(sys.path[1] + '\\' + envelope_file_name + '.file.enc', 'wb') as f:
        f.write(encrypted_file_lines)

    path = os.path.join(sys.path[1] + '\\users\\', receiver_name)
    receiver_rsa_cfg = os.path.join(path, receiver_name + '.rsa')
    rsa_obj = RSA(file=receiver_rsa_cfg)

    decrypted_session_key = oaep_unpad(rsa_obj.oaep_decrypt(encrypted_session_key, 512, 512, rsa_obj.private_key))

    with open(sender_public_key_path, 'r') as pkey_file:
        raw_key = pkey_file.read().rstrip('\n').replace(' ', '')[1:-1].split(',')
    sender_public_key = (int(raw_key[0]), int(raw_key[1]))

    decrypted_hash = oaep_unpad(rsa_obj.oaep_decrypt(encrypted_hash, 512, 512, sender_public_key))

    decrypted_file_name = sys.path[1] + '\\[' + envelope_file_name + ']' + receiver_name + '`s decrypted_file.dec'

    aes_obj = AES(decrypted_session_key)
    aes_obj.decrypt_file(inputf=sys.path[1] + '\\' + os.path.basename(envelope_path) + '.file.enc',
                         outputf=decrypted_file_name)

    with open(decrypted_file_name, 'rb') as f:
        sha256_obj = sha256(f.read())
        my_hash = sha256_obj.hash()

    return my_hash == decrypted_hash
