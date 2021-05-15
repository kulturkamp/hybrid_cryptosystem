import tkinter as tk
from tkinter import messagebox, StringVar
from tkinter import ttk
import sys
import os
from alphabet_detector import AlphabetDetector
from cryptography.RSA import RSA
from PIL import Image, ImageTk
from tkinter.filedialog import askopenfilename
from api.CRapi import create_envelope, open_envelope


class SigninForm(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.geometry('500x200')
        self.resizable(0, 0)
        self.title('Authorization')

        main_frame = tk.Frame(self, bg='dim gray')
        main_frame.pack(fill='both', expand='true')
        main_frame.pack_propagate(0)

        title_styles = {'font': ('Trebuchet MS Bold', 16),
                        'background': 'dim gray',
                        'foreground': '#E1FFFF'}

        text_styles = {'font': ('Verdana', 14),
                       'background': 'dim gray',
                       'foreground': '#E1FFFF'}

        signin_frame = tk.Frame(main_frame, bg='dim gray', relief='groove', bd=2)
        signin_frame.place(rely=0.17, relx=0.1, height=130, width=400)

        title_label = tk.Label(signin_frame, title_styles, text='Authorization')
        title_label.grid(row=0, column=1, columnspan=1)

        label_user = tk.Label(signin_frame, text_styles, text='Username:')
        label_user.grid(row=1, column=0)

        password_label = tk.Label(signin_frame, text_styles, text='Password:')
        password_label.grid(row=2, column=0)

        user_entry = ttk.Entry(signin_frame, width=45, cursor='xterm')
        user_entry.grid(row=1, column=1)

        password_entry = ttk.Entry(signin_frame, width=45, cursor='xterm', show='*')
        password_entry.grid(row=2, column=1)

        signin_button = ttk.Button(signin_frame, text='Sign in',
                                   command=lambda: self.get_signin(user_entry.get(), password_entry.get()))
        signin_button.place(rely=0.75, relx=0.50)

        signup_button = ttk.Button(signin_frame, text='Sign up', command=lambda: self.get_signup())
        signup_button.place(rely=0.75, relx=0.75)

    def get_signup(self):
        SignupForm()

    def get_signin(self, username, password):
        validation = self.validate(username, password)
        if validation:
            global name
            name.set(username)
            tk.messagebox.showinfo('Authorized', 'Welcome, {}'.format(username))
            SigninForm.destroy(self)
            MainForm()

        else:
            tk.messagebox.showerror('Authorization error', 'Incorrect username or password')

    @staticmethod
    def validate(username, password):
        try:
            with open(sys.path[1] + '\\users\\users.txt', 'r') as credentials:
                for line in credentials:
                    line = line.split(':')
                    if line[0] == username and line[1].rstrip('\n') == password:
                        return True
                return False
        except FileNotFoundError:
            print('users.txt file not found')
            return False


class SignupForm(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title('Registration')
        self.geometry('500x200')
        self.resizable(0, 0)

        main_frame = tk.Frame(self, bg='dim gray')
        main_frame.pack(fill='both', expand='true')
        main_frame.pack_propagate(0)

        title_styles = {'font': ('Trebuchet MS Bold', 16),
                        'background': 'dim gray',
                        'foreground': '#E1FFFF'}

        text_styles = {'font': ('Verdana', 14),
                       'background': 'dim gray',
                       'foreground': '#E1FFFF'}

        signup_frame = tk.Frame(main_frame, bg='dim gray', relief='groove', bd=2)
        signup_frame.place(rely=0.15, relx=0.1, height=130, width=400)

        title_label = tk.Label(signup_frame, title_styles, text='Registration')
        title_label.grid(row=0, column=1, columnspan=1)

        user_label = tk.Label(signup_frame, text_styles, text='Username:')
        user_label.grid(row=1, column=0)

        password_label = tk.Label(signup_frame, text_styles, text='Password:')
        password_label.grid(row=2, column=0)

        user_entry = ttk.Entry(signup_frame, width=45, cursor='xterm')
        user_entry.grid(row=1, column=1)

        password_entry = ttk.Entry(signup_frame, width=45, cursor='xterm', show='*')
        password_entry.grid(row=2, column=1)

        signup_button = ttk.Button(signup_frame, text='Sign up',
                                   command=lambda: self.signup(user_entry.get(), password_entry.get()))
        signup_button.place(rely=0.75, relx=0.5)

    def signup(self, username, password):
        validation = self.validate_username(username) & self.validate_password(password)
        if not validation:
            SignupForm.destroy(self)
            SignupForm()
        else:
            credentials = open(sys.path[1] + '\\users\\users.txt', 'a')
            credentials.write(f'{username}:{password}' + '\n')
            credentials.close()

            rsa_obj = RSA()
            path = os.path.join(sys.path[1] + '\\users\\', username)
            os.mkdir(path)
            rsa_obj.save_config(os.path.join(path, username + '.rsa'))

            tk.messagebox.showinfo('Information', 'Registration successful')
            SignupForm.destroy(self)

    @staticmethod
    def validate_username(username):
        ad = AlphabetDetector()
        if not ad.only_alphabet_chars(username, 'LATIN'):
            tk.messagebox.showerror('Information', 'Username must contain latin chars and/or numbers')
            return False
        try:
            with open(sys.path[1] + '\\users\\users.txt', 'r') as credentials:
                for line in credentials:
                    line = line.split(':')
                    if line[0] == username:
                        tk.messagebox.showerror('Information', 'Username already exists')
                        return False
            return True
        except FileNotFoundError:
            print('users.txt file not found')
            return False

    @staticmethod
    def validate_password(password):
        ad = AlphabetDetector()
        if len(password) <= 3:
            tk.messagebox.showerror('Information', 'Password too short (at least 4 symbols)')
            return False
        elif not ad.only_alphabet_chars(password, 'LATIN'):
            tk.messagebox.showerror('Information', 'Password must contain latin chars and/or numbers')
            return False
        return True


class MainForm(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title('Cryptography session')
        self.geometry('1024x512')
        self.resizable(0, 0)
        self.session_name = name.get()

        self.receiver_path = ''
        self.receiver_entry_text = StringVar()

        self.to_encrypt_file_path = ''
        self.to_encrypt_file_entry_text = StringVar()

        self.envelope_to_open_path = ''
        self.envelope_to_open_entry_text = StringVar()

        self.sender_public_key_file = ''
        self.sender_public_key_file_entry_text = StringVar()

        main_frame = tk.Frame(self, bg='dim gray')
        main_frame.pack(fill='both', expand='true')
        main_frame.pack_propagate(0)

        title_styles = {'font': ('Trebuchet MS Bold', 14),
                        'background': 'dim gray',
                        'foreground': '#E1FFFF'}
        text_styles = {'font': ('Verdana', 12),
                       'background': 'dim gray',
                       'foreground': '#E1FFFF'}
        style = ttk.Style()
        style.theme_use('alt')
        style.configure('Img.TButton', borderwidth=0, highlightthickness=0, background='dim gray')
        style.configure('Choose.TButton', background='light gray', font=('Verdana', 7))


        title_label = tk.Label(main_frame, title_styles, text=self.session_name + '`s session')
        title_label.grid(row=0, column=0)

        # session key section
        session_key_label = tk.Label(main_frame, text_styles, text='Session key:')
        session_key_label.grid(row=1, column=0)

        session_key_entry = ttk.Entry(main_frame, width=60, cursor='xterm')
        session_key_entry.grid(row=1, column=1)
        session_key_entry.insert(0, os.urandom(32).decode('LATIN'))

        dice_img = Image.open(sys.path[1] + '\\resources\\dice.png')
        dice_img = dice_img.resize((30, 30), Image.ANTIALIAS)
        global ph_dice_img
        ph_dice_img = ImageTk.PhotoImage(dice_img)



        generate_skey_button = ttk.Button(main_frame, image=ph_dice_img,
                                          command=lambda: self.update_session_key_entry(session_key_entry),
                                          style='Img.TButton')
        generate_skey_button.grid(row=1, column=2)

        # create envelope section
        create_env_frame = tk.Frame(main_frame, bg='dim gray', relief='groove', bd=2)
        create_env_frame.place(rely=0.15, relx=0.1, height=175, width=800)

        env_closed_img = Image.open(sys.path[1] + '\\resources\\envelope_closed.png')
        env_closed_img = env_closed_img.resize((100, 100), Image.ANTIALIAS)
        global ph_env_closed_img
        ph_env_closed_img = ImageTk.PhotoImage(env_closed_img)

        create_env_button = ttk.Button(create_env_frame, image=ph_env_closed_img,
                                       style='Img.TButton',
                                       command=lambda: self.create_envelope_wrapper(self.session_name,
                                                                                    self.receiver_path,
                                                                                    session_key_entry.get(),
                                                                                    self.to_encrypt_file_path))
        create_env_button.place(rely=0.1, relx=0.4)



        # choose receiver section
        choose_receiver_button = ttk.Button(create_env_frame, text='Receiver`s public RSA key',
                                            command=lambda: self.choose_receiver(),
                                            style='Choose.TButton')
        choose_receiver_button.place(rely=0.7, relx=0)

        receiver_entry = ttk.Entry(create_env_frame, textvariable=self.receiver_entry_text, width=80)
        receiver_entry.place(rely=0.7, relx=0.2)

        # choose file to encrypt section
        choose_toenc_file_button = ttk.Button(create_env_frame, text='Choose file to encrypt',
                                              command=lambda: self.choose_file_to_encrypt(),
                                              style='Choose.TButton')
        choose_toenc_file_button.place(rely=0.85, relx=0)

        toencr_file_entry = ttk.Entry(create_env_frame, textvariable=self.to_encrypt_file_entry_text, width=80)
        toencr_file_entry.place(rely=0.85, relx=0.2)

        # choose envelope to open section
        open_env_frame = tk.Frame(main_frame, bg='dim gray', relief='groove', bd=2)
        open_env_frame.place(rely=0.6, relx=0.1, height=175, width=800)

        env_opened_img = Image.open(sys.path[1] + '\\resources\\envelope_opened.png')
        env_opened_img = env_opened_img.resize((100, 100), Image.ANTIALIAS)
        global ph_env_opened_img
        ph_env_opened_img = ImageTk.PhotoImage(env_opened_img)

        open_env_button = ttk.Button(open_env_frame, image=ph_env_opened_img,
                                     style='Img.TButton',
                                     command=lambda: self.open_envelope_wrapper(self.session_name,
                                                                                self.sender_public_key_file,
                                                                                self.envelope_to_open_path))
        open_env_button.place(rely=0.1, relx=0.4)



        # choose envelope section
        choose_envelope_button = ttk.Button(open_env_frame, text='Choose envelope to open',
                                            command=lambda: self.choose_envelope_to_open(),
                                            style='Choose.TButton')
        choose_envelope_button.place(rely=0.7, relx=0)

        choose_envelope_entry = ttk.Entry(open_env_frame, textvariable=self.envelope_to_open_entry_text, width=80)
        choose_envelope_entry.place(rely=0.7, relx=0.2)

        # choose sender section
        choose_sender_button = ttk.Button(open_env_frame, text='Choose sender`s public key',
                                          command=lambda: self.choose_sender_public_key_file(),
                                          style='Choose.TButton')
        choose_sender_button.place(rely=0.85, relx=0)

        choose_sender_entry = ttk.Entry(open_env_frame, textvariable=self.sender_public_key_file_entry_text, width=80)
        choose_sender_entry.place(rely=0.85, relx=0.2)

    def update_session_key_entry(self, entry):
        entry.delete(0, tk.END)
        new_key = os.urandom(32)
        entry.insert(0, new_key.decode('LATIN'))

    def choose_receiver(self):
        self.receiver_path = askopenfilename()
        self.receiver_entry_text.set(self.receiver_path)

    def choose_file_to_encrypt(self):
        self.to_encrypt_file_path = askopenfilename()
        self.to_encrypt_file_entry_text.set(self.to_encrypt_file_path)

    def choose_envelope_to_open(self):
        self.envelope_to_open_path = askopenfilename()
        self.envelope_to_open_entry_text.set(self.envelope_to_open_path)

    def choose_sender_public_key_file(self):
        self.sender_public_key_file = askopenfilename()
        self.sender_public_key_file_entry_text.set(self.sender_public_key_file)

    @staticmethod
    def create_envelope_wrapper(a, b, c, d):
        if not c:
            tk.messagebox.showerror('Information', 'Generate or enter a session key (32 symbol length).')
        elif len(c) != 32:
            tk.messagebox.showerror('Information', 'Session key must be 32 symbol long.')

        else:
            if not isinstance(c, bytes):
                c = c.encode('LATIN')
            try:
                create_envelope(a, b, c, d)
                tk.messagebox.showinfo('Information', 'Envelope created successfully.')
            except:
                tk.messagebox.showerror('Information', 'Error occurred during envelope creation.')

    @staticmethod
    def open_envelope_wrapper(a, b, c):
        try:
            integrity = open_envelope(a, b, c)
            if integrity:
                tk.messagebox.showinfo('Information', 'Envelope opened successfully. File integrity secured.')
            else:
                tk.messagebox.showerror('Information', 'File integrity was not secured.')
        except:
            tk.messagebox.showerror('Information', 'Error occurred during envelope opening.')


root = SigninForm()
name = StringVar()
root.mainloop()
