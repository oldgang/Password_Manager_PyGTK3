import gi
import base64
import sys
import secrets
import string
import os.path
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ast
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk


masterPassword = ''
masterPasswordHashHex = ''
fernetKey = Fernet(Fernet.generate_key())
storedData = list()
encryptedData = fernetKey.encrypt('start'.encode('utf-8'))


def length_isvalid(length):
    if length.isnumeric():
        if int(length) > 0:
            return True
    return False


def checkbox_isvalid(letters, digits, special_characters):
    if not letters:
        if not digits:
            if not special_characters:
                return False
    return True


def password_generator(length, letters, digits, special_characters):
    characters = ''
    if letters:
        characters += string.ascii_letters
    if digits:
        characters += string.digits
    if special_characters:
        characters += string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


def master_exists():
    if os.path.exists("MasterPassword.txt"):
        return True  # -> login screen
    else:
        return False  # -> registration screen


def save_master_to_file():
    global masterPassword
    global masterPasswordHashHex
    master_password_hash = hashlib.sha512(masterPassword.encode('utf-8'))
    masterPasswordHashHex = master_password_hash.hexdigest()
    with open("MasterPassword.txt", 'w') as masterFile:
        masterFile.write(masterPasswordHashHex)
    masterFile.close()


def compare_master():
    global masterPassword
    global masterPasswordHashHex
    master_password_hash = hashlib.sha512(masterPassword.encode('utf-8'))
    masterPasswordHashHex = master_password_hash.hexdigest()
    with open("MasterPassword.txt", 'r') as masterFile:
        stored_master_password_hash_hex = masterFile.read()
    masterFile.close()
    if masterPasswordHashHex == stored_master_password_hash_hex:
        return True
    else:
        return False


def display_error(parent, message):
    error_window = Gtk.Window(title="Błąd")
    label = Gtk.Label()
    label.set_text(message)
    label.set_margin_top(10)
    label.set_margin_bottom(10)
    label.set_margin_start(10)
    label.set_margin_end(10)
    error_window.add(label)
    error_window.set_resizable(False)
    error_window.set_position(Gtk.WindowPosition.CENTER)
    error_window.show_all()


def data_exists():
    if os.path.exists("data.txt"):
        return True
    else:
        return False


def data_isvalid(self, site, login, password):
    if not len(site) > 0:
        display_error(self, "Strona nie może być pusta")
        return False
    if not len(login) > 0:
        display_error(self, "Login nie może być pusty")
        return False
    if not len(password) > 0:
        display_error(self, "Hasło nie może być puste")
        return False
    return True


def load_data():
    global storedData
    global encryptedData
    with open('data.txt', 'r') as dataFile:
        encryptedData = dataFile.read()[2:-1:1].encode('utf-8')
    decrypt_data()


def save_data():
    global encryptedData
    global storedData
    encrypt_data()
    with open('data.txt', 'w') as dataFile:
        dataFile.write(str(encryptedData))


def generate_fernet_key():
    global masterPassword
    global fernetKey
    password = masterPassword.encode('utf-8')
    salt = masterPassword.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fernetKey = Fernet(key)


def encrypt_data():
    global storedData
    global encryptedData
    global fernetKey
    encryptedData = fernetKey.encrypt(str(storedData).encode('utf-8'))


def decrypt_data():
    global storedData
    global encryptedData
    global fernetKey
    decrypted_data = fernetKey.decrypt(encryptedData)
    decrypted_data = decrypted_data.decode('utf-8')
    storedData = ast.literal_eval(decrypted_data)


def erase_data(arg):
    if master_exists():
        os.remove("MasterPassword.txt")
    if data_exists():
        os.remove("data.txt")
    Gtk.main_quit()


################################################################################

class MasterPasswordWindow(Gtk.Window):
    def __init__(self):
        builder = Gtk.Builder()
        builder.add_from_file("Interface.glade")
        super().__init__(title="Zmiana hasła głównego")
        # get objects
        self.master_window = builder.get_object("MasterPasswordWindow")
        self.radio_manual = builder.get_object("MPW_radio_manual")
        self.radio_automatic = builder.get_object("MPW_radio_automatic")
        self.master1 = builder.get_object("MPW_master1")
        self.master2 = builder.get_object("MPW_master2")
        self.generated = builder.get_object("MPW_generated")
        self.save = builder.get_object("MPW_save")
        self.generate = builder.get_object("MPW_generate")
        self.letters = builder.get_object("MPW_letters")
        self.digits = builder.get_object("MPW_digits")
        self.special_characters = builder.get_object("MPW_special_characters")
        self.generated_length = builder.get_object("MPW_length")
        # connect functions
        self.master_window.connect('delete-event', self.on_destroy)
        self.generate.connect('clicked', self.generate_password)
        self.save.connect('clicked', self.save_master_password)
        # clear text areas
        self.master1.set_text("")
        self.master2.set_text("")
        self.generated.set_text("")
        self.generated_length.set_text('')
        # show window
        self.master_window.show_all()

    def on_destroy(self, widget, event):
        widget.destroy()
        return True

    def save_master_password(self, widget):
        global masterPassword
        manual = self.radio_manual.get_active()
        automatic = self.radio_automatic.get_active()
        if automatic:
            masterPassword = self.generated.get_text()
        if manual:
            password1 = self.master1.get_text()
            password2 = self.master2.get_text()
            # check if passwords are the same
            if not password1 == password2:
                display_error(self, "Hasła nie są identyczne")
                return
            # check if passwords are valid
            if not (len(password1) > 0 and len(password2) > 0):
                display_error(self, "Hasło nie może mieć zerowej długości")
                return
            masterPassword = self.master1.get_text()
        save_master_to_file()
        self.master_window.hide()

    def generate_password(self, widget):
        if not self.radio_automatic.get_active():
            return
        length = self.generated_length.get_text()
        if not length_isvalid(length):
            display_error(self, "Nieprawidłowa długość hasła")
            return
        length = int(length)
        letters = self.letters.get_active()
        digits = self.digits.get_active()
        special_characters = self.special_characters.get_active()
        # check if there is at least one checkbox selected
        if not checkbox_isvalid(letters, digits, special_characters):
            display_error(self, "Zaznacz przynajmniej jeden typ znaków do wygenerowania hasła")
            return
        password = password_generator(length, letters, digits, special_characters)
        self.generated.set_text(password)


class AddPasswordWindow(Gtk.Window):
    def __init__(self):
        builder = Gtk.Builder()
        builder.add_from_file("Interface.glade")
        super().__init__(title="Dodawanie hasła")
        # get objects
        self.add_password_window = builder.get_object("AddPasswordWindow")
        self.site = builder.get_object("APW_site")
        self.login = builder.get_object("APW_login")
        self.password = builder.get_object("APW_password")
        self.radio_manual = builder.get_object("APW_radio_manual")
        self.radio_automatic = builder.get_object("APW_radio_automatic")
        self.letters = builder.get_object("APW_letters")
        self.digits = builder.get_object("APW_digits")
        self.special_characters = builder.get_object("APW_special_characters")
        self.generated_length = builder.get_object("APW_length")
        self.generated = builder.get_object("APW_generated")
        self.save = builder.get_object("APW_save")
        self.generate = builder.get_object("APW_generate")
        # connect functions
        self.add_password_window.connect('delete-event', self.on_destroy)
        self.generate.connect('clicked', self.generate_password)
        self.save.connect('clicked', self.add_data)
        # clear text areas
        self.site.set_text("")
        self.login.set_text("")
        self.password.set_text("")
        self.generated.set_text("")
        self.generated_length.set_text('')
        # show window
        self.add_password_window.show_all()

    def on_destroy(self, widget, event):
        widget.destroy()
        return True

    def add_data(self, widget):
        site = self.site.get_text()
        login = self.login.get_text()
        if self.radio_automatic.get_active():
            password = self.generated.get_text()
        if self.radio_manual.get_active():
            password = self.password.get_text()
        if not len(password) > 0:
            display_error(self, "Hasło nie może być puste")
            return
        global storedData
        if not data_isvalid(self, site, login, password):
            return
        data = [site, login, password]
        storedData.append(data)
        save_data()
        self.add_password_window.destroy()

    def generate_password(self, widget):
        if not self.radio_automatic.get_active():
            return
        length = self.generated_length.get_text()
        if not length_isvalid(length):
            display_error(self, "Nieprawidłowa długość hasła")
            return
        length = int(length)
        letters = self.letters.get_active()
        digits = self.digits.get_active()
        special_characters = self.special_characters.get_active()
        # check if there is at least one checkbox selected
        if not checkbox_isvalid(letters, digits, special_characters):
            display_error(self, "Zaznacz przynajmniej jeden typ znaków do wygenerowania hasła")
            return
        password = password_generator(length, letters, digits, special_characters)
        self.generated.set_text(password)


class RemovePasswordWindow(Gtk.Window):
    def __init__(self):
        builder = Gtk.Builder()
        builder.add_from_file("Interface.glade")
        super().__init__(title="Usuwanie hasła")
        # get objects
        self.remove_password_window = builder.get_object("RemovePasswordWindow")
        self.site = builder.get_object("RPW_site")
        self.delete_button = builder.get_object("RPW_delete")
        # connect functions
        self.remove_password_window.connect('delete-event', self.on_destroy)
        self.delete_button.connect('clicked', self.delete_password)
        # clear text areas
        self.site.set_text("")
        # show window
        self.remove_password_window.show_all()

    def on_destroy(self, widget, event):
        widget.destroy()
        return True

    def delete_password(self, widget):
        global storedData
        site_to_delete = self.site.get_text()
        if not len(site_to_delete) > 0:
            display_error(self, "Pole nie może być puste.")
            return
        site_found = False
        for siteData in storedData:
            if site_to_delete in siteData[0]:
                site_found = True
                storedData.remove(siteData)
        if not site_found:
            display_error(self, "Nie znaleziono danych dla podanej strony.")
            return
        save_data()
        self.remove_password_window.hide()


class ShowPasswordsWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="Lista wszystkich danych")
        self.set_border_width(10)
        self.set_default_size(800,600)
        self.set_resizable(False)
        self.set_position(Gtk.WindowPosition.CENTER)

        # Setting up the self.grid in which the elements are to be positioned
        self.grid = Gtk.Grid()
        self.grid.set_column_homogeneous(True)
        self.grid.set_row_homogeneous(True)
        self.add(self.grid)
        global storedData
        # Creating the ListStore model
        self.sitedata_liststore = Gtk.ListStore(str, str, str)
        for siteData in storedData:
            self.sitedata_liststore.append(siteData)
        self.current_filter_language = None

        # Creating the filter, feeding it with the liststore model
        self.language_filter = self.sitedata_liststore.filter_new()
        self.language_filter.set_visible_func(self.language_filter_func)

        # creating the treeview, making it use the filter as a model, and adding the columns
        self.treeview = Gtk.TreeView(model=self.language_filter)
        for i, column_title in enumerate(
            ["Strona", "Login", "Hasło"]
        ):
            renderer = Gtk.CellRendererText()
            renderer.set_property('editable', True)
            column = Gtk.TreeViewColumn(column_title, renderer, text=i)
            self.treeview.append_column(column)

        self.scrollable_treelist = Gtk.ScrolledWindow()
        self.scrollable_treelist.set_vexpand(True)
        self.grid.attach(self.scrollable_treelist, 0, 0, 8, 10)
        self.scrollable_treelist.add(self.treeview)
        self.treeview.columns_autosize()
        self.show_all()

    def language_filter_func(self, model, iter, data):
        if (
            self.current_filter_language is None
            or self.current_filter_language == "None"
        ):
            return True
        else:
            return model[iter][2] == self.current_filter_language


class LoginWindow(Gtk.Window):
    def __init__(self):
        builder = Gtk.Builder()
        builder.add_from_file("Interface.glade")
        super().__init__(title="Ekran Logowania")
        self.login_window = builder.get_object("LoginWindow")
        self.login_window.connect("destroy", Gtk.main_quit)
        self.entry_password = builder.get_object("password")
        self.button_login = builder.get_object("login")
        self.button_login.connect("clicked", self.login)
        self.login_window.show_all()

    def login(self, widget):
        password = self.entry_password.get_text()
        if not len(password) > 0:
            display_error(self, "Hasło nie może mieć zerowej długości")
            return
        global masterPassword
        masterPassword = password
        if compare_master():
            main_window = MainWindow()
            self.login_window.hide()
        else:
            display_error(self, "Nieprawidłowe hasło")
            return


class RegistrationWindow(Gtk.Window):
    def __init__(self):
        builder = Gtk.Builder()
        builder.add_from_file("Interface.glade")
        super().__init__(title="Ekran Rejestracji")
        self.registration_window = builder.get_object("RegistrationWindow")
        self.registration_window.connect("destroy", Gtk.main_quit)
        self.entry_master1 = builder.get_object("RW_master1")
        self.entry_master2 = builder.get_object("RW_master2")
        self.button_register = builder.get_object("RW_register")
        self.button_register.connect("clicked", self.register)
        self.registration_window.show_all()

    def register(self, widget):
        master1 = self.entry_master1.get_text()
        master2 = self.entry_master2.get_text()
        if not master1 == master2:
            display_error(self, "Hasła nie są identyczne")
            return
        if not (len(master1) > 0 and len(master2) > 0):
            display_error(self, "Hasło nie może być puste")
            return
        # update global variable and save master to file
        global masterPassword
        masterPassword = master1
        save_master_to_file()
        # if registration is complete, open main window and close this one
        main_window = MainWindow()
        self.registration_window.hide()


class InformationWindow(Gtk.Window):
    def __init__(self):
        builder = Gtk.Builder()
        builder.add_from_file("Interface.glade")
        super().__init__(title="Informacje o programie")
        self.info_window = builder.get_object("InformationWindow")
        self.info_label = builder.get_object("info_label")
        self.info_window.connect('delete-event', self.on_destroy)
        self.info_window.show_all()

    def on_destroy(self, widget, event):
        widget.hide()
        return True


class MainWindow(Gtk.Window):
    def __init__(self):
        builder = Gtk.Builder()
        builder.add_from_file("Interface.glade")
        super().__init__(title="Menadżer haseł")
        self.main_window = builder.get_object("MainWindow")
        self.button_master = builder.get_object("button_master")
        self.button_add = builder.get_object('button_add')
        self.button_remove = builder.get_object('button_remove')
        self.button_show = builder.get_object('button_show')
        self.menu_erase_data = builder.get_object('menu_erase_data')
        self.menu_info = builder.get_object('menu_info')
        self.menu_exit = builder.get_object('menu_exit')
        self.main_window.connect("destroy", Gtk.main_quit)
        self.button_master.connect("clicked", self.create_master_window)
        self.button_add.connect('clicked', self.create_add_password_window)
        self.button_remove.connect('clicked', self.create_remove_password_window)
        self.button_show.connect('clicked', self.create_show_passwords_window)
        self.menu_info.connect('activate', self.create_info_window)
        self.menu_exit.connect('activate', Gtk.main_quit)
        self.menu_erase_data.connect('activate', erase_data)
        self.main_window.show_all()

    def create_master_window(self, widget):
        self.master_window = MasterPasswordWindow()

    def create_add_password_window(self, widget):
        self.add_password_window = AddPasswordWindow()

    def create_remove_password_window(self, widget):
        self.remove_password_window = RemovePasswordWindow()

    def create_show_passwords_window(self, widget):
        self.show_passwords_window = ShowPasswordsWindow()

    def create_info_window(self, widget):
        self.info_window = InformationWindow()


# main:
if master_exists():
    login_window = LoginWindow()
else:
    registration_window = RegistrationWindow()

generate_fernet_key()
if os.path.exists('data.txt'):
    load_data()

Gtk.main()
