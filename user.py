from RSA import RSA, oaep_padding
from AES import AES, get_iv
from sha256 import sha256


class User:
    def __init__(self, name, session_key):
        self.rsa = RSA()
        self.name = name
        self.m_key = session_key
        self.message = ""
        self.envelope = []

    def create_envelope(self, message, other):
        self.message = message

        aes_obj = AES(self.m_key)
        iv = get_iv()
        enc_msg = aes_obj.encrypt(message, iv)

        enc_mkey = self.rsa.encrypt(self.m_key, other.rsa.public_key)

        sha256_obj = sha256(message)
        msg_hash = sha256_obj.hash()
        g = h = 512
        enc_hash = self.rsa.oaep_encrypt(msg_hash, g, h, self.rsa.private_key)

        return [iv, enc_mkey, enc_msg, enc_hash]

    def receive_envelope(self, envelope):
        self.envelope = envelope

    def send_envelope(self, message, other):
        self.envelope = self.create_envelope(message, other)
        other.receive_envelope(self.envelope)

    def open_envelope(self, sender):
        iv, enc_mkey, enc_msg, enc_hash = self.envelope

        dec_key = self.rsa.decrypt(enc_mkey, self.rsa.private_key)

        aes_obj = AES(dec_key)
        dec_msg = aes_obj.decrypt(enc_msg, iv)
        self.message = dec_msg
        g = h = 512
        dec_hash_raw = sender.rsa.oaep_decrypt(enc_hash, g, h, sender.rsa.public_key)

        self.envelope = [iv, dec_key, dec_msg, dec_hash_raw]

    def chek_msg_inegrity(self):
        sha256_obj = sha256(self.envelope[2])
        my_hash = sha256_obj.hash()
        g = h = 512
        _, padded = oaep_padding(my_hash, g, h)
        if padded == self.envelope[3]:
            print("message integrity secured")
        else:
            print("message is corrupted")


if __name__ == '__main__':
    mkey = b'a'*32
    alice = User('alice', mkey)
    bob = User('bob', mkey)

