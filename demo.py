from flask import Flask, render_template, request
from cryptography.RSA import RSA, oaep_unpad
from cryptography.AES import AES, get_iv
from cryptography.sha256 import sha256
import os


def generate_masterkey(l=32):
    return os.urandom(l)


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
        g = h = 512
        enc_mkey = self.rsa.oaep_encrypt(self.m_key, g, h, other.rsa.public_key)

        sha256_obj = sha256(message)
        msg_hash = sha256_obj.hash()

        enc_hash = self.rsa.oaep_encrypt(msg_hash, g, h, self.rsa.private_key)

        return [iv, enc_mkey, enc_msg, enc_hash]

    def receive_envelope(self, envelope):
        self.envelope = envelope

    def send_envelope(self, message, other):
        self.envelope = self.create_envelope(message, other)
        other.receive_envelope(self.envelope)

    def open_envelope(self, sender):
        iv, enc_mkey, enc_msg, enc_hash = self.envelope
        g = h = 512
        dec_key = oaep_unpad(self.rsa.oaep_decrypt(enc_mkey, g, h, self.rsa.private_key))

        aes_obj = AES(dec_key)
        dec_msg = aes_obj.decrypt(enc_msg, iv)
        self.message = dec_msg

        dec_hash = oaep_unpad(self.rsa.oaep_decrypt(enc_hash, g, h, sender.rsa.public_key))

        self.envelope = [iv, dec_key, dec_msg, dec_hash]

        sha_obj = sha256(dec_msg)
        my_hash = sha_obj.hash()
        return dec_hash == my_hash



app = Flask(__name__)


@app.route('/')
def main():
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt():
    if request.method == 'POST':
        sender_name = request.form['sender']
        receiver_name = request.form['receiver']
        msg = request.form['message']

        session_key = generate_masterkey(32)
        sender = User(sender_name, session_key)
        receiver = User(receiver_name, session_key)

        sender.send_envelope(msg.encode('utf-8'), receiver)
        integrity = receiver.open_envelope(sender)
        if integrity:
            return render_template('index.html', integrity='integrity secured',
                                   key="decrypted session key: " + receiver.envelope[1],
                                   encr="encrypted message: " + str(sender.envelope[2]),
                                   decr="decrypted message: " + str(receiver.message))
        elif not integrity:
            render_template('index.html', integrity='integrity not secured')
        else:
            return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)