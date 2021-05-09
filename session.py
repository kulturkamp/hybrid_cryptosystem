import os
from user import User


def generate_masterkey(l=32):
    return os.urandom(l)


def demo(sender, receiver, message=b'my secret massage'):
    print("{0} is going to send {1} this message: {2}".format(sender.name, receiver.name, message))
    sender.send_envelope(message, receiver)
    print("envelope that was sent looks like this: \nencrypted session key: {0}\nencrypted message: {1}\n"
          "encrypted message hash: {2}".format(sender.envelope[1], sender.envelope[2],
                                               sender.envelope[3]))

    receiver.open_envelope(sender)
    receiver.chek_msg_inegrity()
    print("decrypted message: {}".format(receiver.message))


if __name__ == '__main__':
    # session key length: 16 24 32
    session_key = generate_masterkey(32)
    Alice = User('Alice', session_key)
    Bob = User('Bob', session_key)
    demo(Alice, Bob)
