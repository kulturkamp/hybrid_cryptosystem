from flask import Flask, render_template, request
from user import User
from session import generate_masterkey


app = Flask(__name__)


@app.route('/')
def main():
    return render_template('index.html')


@app.route('/send', methods=['POST'])
def send():
    if request.method == 'POST':
        sender_name = request.form['sender']
        receiver_name = request.form['receiver']
        msg = request.form['message']

        session_key = generate_masterkey(32)
        sender = User(sender_name, session_key)
        receiver = User(receiver_name, session_key)

        sender.send_envelope(msg.encode('utf-8'), receiver)
        receiver.open_envelope(sender)
        if receiver.chek_msg_inegrity():
            return render_template('index.html', integrity='integrity secured',
                                   encr="encrypted message: " + str(sender.envelope[2]),
                                   decr="decrypted message: " + str(receiver.message))
        elif not receiver.chek_msg_inegrity():
            render_template('index.html', integrity='integrity not secured')
        else:
            return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)