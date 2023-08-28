from datetime import datetime
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import tkinter.filedialog as tkFileDialog

from PGPKeyPair import PGPKeyPair
from PGPKeyRing import PGPKeyRing
from SafeEmails.ControlFlow import ControlFlow


class ViewPublicKeyWindow(tk.Toplevel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            self.title("Public Key")
            self.geometry("%dx%d+%d+%d" % (400, 320, self.master.winfo_x() + 1520 / 3, self.master.winfo_y() + 1080 / 3))
            self.public_key_textbox = tk.Text(self, width=100)
            self.public_key_textbox.grid(row=0, column=0, padx=(20,20), pady=(20,20), sticky="nsew")
            cf = ControlFlow()
            print(cf.get_last_key())
            pem = PGPKeyRing.get_public_pem(cf.get_last_key())
            self.public_key_textbox.insert("0.0",pem)
            self.public_key_textbox.configure(state="disabled")
            self.after(100, self.lift)
            self.email = None
            self.name = None
        except:
            pass

class PGPApplicationGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.control_flow = ControlFlow()


        self.msg_file_path = "../message/myMsg.txt"
        if os.path.isfile(self.msg_file_path) is False:
            self.path_save = self.msg_file_path

        self.title("PGP Key Manager")
        # self.attributes('-fullscreen', True)
        self.configure(bg="WHITE")
        self.columnconfigure(12, {'minsize': 10})
        self.key_ring = PGPKeyRing()
        self.email_label = tk.Label(self, text="Email:")
        self.email_entry = tk.Entry(self)

        self.name_label = tk.Label(self, text="Name:")
        self.name_entry = tk.Entry(self)
        self.algorithm_label = tk.Label(self, text="Algorithm:")
        self.algorithm_var = tk.StringVar(value="RSA")
        self.password_label = tk.Label(self, text="Password:")
        self.password_entry = tk.Entry(self, show='*')
        self.algorithm_dropdown = tk.OptionMenu(self, self.algorithm_var, "RSA", "DSA", "ElGamal")

        self.key_size_label = tk.Label(self, text="Key Size:")
        self.key_size_var = tk.IntVar(value=2048)
        self.key_size_dropdown = tk.OptionMenu(self, self.key_size_var, 1024, 2048)

        self.generate_button = tk.Button(self, text="Generate Key Pair", command=self.generate_key_pair)
        self.export_public_button = tk.Button(self, text="Export Public Key", command=self.export_public_key)
        self.export_private_button = tk.Button(self, text="Export Private Key", command=self.export_private_key)
        self.unlockPassword_label = tk.Label(self, text="Enter password")
        self.unlockPassword_entry = tk.Entry(self)
        self.keyID_label = tk.Label(self, text="Key ID:")
        self.keyID_entry = tk.Entry(self)
        # self.import_info_label = tk.Label(self, text="Import User Info")
        # self.import_email_label = tk.Label(self, text="Email:")
        # self.import_email_entry = tk.Entry(self)
        # self.import_name_label = tk.Label(self, text="Name:")
        # self.import_name_entry = tk.Entry(self)

        self.keyID_label_delete = tk.Label(self, text="Key ID:")
        self.keyID_entry_delete = tk.Entry(self)
        self.delete_key_pair_button = tk.Button(self, text="Delete key pair", command=self.delete_key_pair)
        # my public key ring
        self.table = ttk.Treeview(self, columns=("User ID", "Key ID", "Algorithm", "Timestamp"), show="headings")
        self.table.heading("User ID", text="User ID")
        self.table.heading("Key ID", text="Key ID")
        self.table.heading("Algorithm", text="Algorithm")
        self.table.heading("Timestamp", text="Timestamp")
        self.my_keys = tk.Label(self, text="My Keys")
        self.table.bind("<Button-3>", self.popup)

        # my public key ring
        self.table_contacts = ttk.Treeview(self, columns=("User ID", "Key ID", "Algorithm", "Timestamp"), show="headings")
        self.table_contacts.heading("User ID", text="User ID")
        self.table_contacts.heading("Key ID", text="Key ID")
        self.table_contacts.heading("Algorithm", text="Algorithm")
        self.table_contacts.heading("Timestamp", text="Timestamp")
        self.my_contacts = tk.Label(self, text="My Contacts")

        # import keys
        self.import_private_key_label = tk.Label(self, text="Import private key")
        self.for_file_label = tk.Label(self, text="PEM File")
        self.for_file_entry = tk.Button(self, text="Choose file", command=self.search_for_file_path)
        self.import_private_button = tk.Button(self, text="Import Private Key", command=self.import_private_key)
        self.path_import_private = None
        self.import_enter_password_label = tk.Label(self, text="Enter password")
        self.import_enter_password_entry = tk.Entry(self, show='*')



        self.import_public_key_label = tk.Label(self, text="Import public key")
        self.import_public_button = tk.Button(self, text="Import Public Key", command=self.import_public_key)
        self.path_import_public = None

        self.import_algorithm_var = tk.StringVar()
        self.import_key_dropdown = tk.OptionMenu(self, self.import_algorithm_var, "RSA", "DSA", "ElGamal")

        # send
        self.send_message_label = tk.Label(self, text="Send message")
        self.to_label = tk.Label(self, text="To:")
        self.to_entry = tk.Entry(self)
        self.privacy_label = tk.Label(self, text="Privacy:")
        self.privacy_entry = tk.Entry(self)
        self.authentication_label = tk.Label(self, text="Authentication:")
        self.authentication_entry = tk.Entry(self)
        var1 = tk.IntVar()
        var2 = tk.IntVar()
        self.compression = tk.Checkbutton(self, text='Compression', variable=var1, onvalue=1, offvalue=0)
        self.radix_64 = tk.Checkbutton(self, text='Radix_64', variable=var2, onvalue=1, offvalue=0)
        self.msg_label = tk.Label(self, text="Message text:")
        self.msg_entry = tk.Text(self, height=10, width=50)
        self.send_button = tk.Button(self, text="Send", command=self.send_message)

        # receive
        self.receive_message_label = tk.Label(self, text="Receive message")
        self.receive_password_label = tk.Label(self, text="Password:")
        self.receive_password_entry = tk.Entry(self)
        self.receive_info_button = tk.Button(self, text="Open message", command=self.open_message)
        self.receive_info_text = tk.Label(self, text="")
        self.receive_save_message_label = tk.Label(self, text="File path to save message:")
        self.search_for_file_button2 = tk.Button(self, text="Choose file", command=self.search_for_file_path)
        self.receive_save_message_button = tk.Button(self, text="Save message", command=self.send_message)
        # self.separatorH = ttk.Separator(self, orient='horizontal')
        # self.separatorH2 = ttk.Separator(self, orient='horizontal')
        self.separatorV = ttk.Separator(self, orient='vertical')
        self.separatorV2 = ttk.Separator(self, orient='vertical')

        self.separatorH = ttk.Separator(self, orient='horizontal')
        self.separatorH2 = ttk.Separator(self, orient='horizontal')
        self.separatorH3 = ttk.Separator(self, orient='horizontal')

        # self.separatorH.grid(column=0, row=4, rowspan=20, sticky='ns')
        self.name_label.grid(row=1, column=0, padx=5, pady=5)
        self.name_entry.grid(row=1, column=1, padx=5, pady=5)
        self.email_label.grid(row=0, column=0, padx=5, pady=5)
        self.email_entry.grid(row=0, column=1, padx=5, pady=5)

        self.algorithm_label.grid(row=2, column=0, padx=5, pady=5)
        self.algorithm_dropdown.grid(row=2, column=1, padx=5, pady=5)
        self.key_size_label.grid(row=3, column=0, padx=5, pady=5)
        self.key_size_dropdown.grid(row=3, column=1, padx=5, pady=5)
        self.password_label.grid(row=4, column=0, padx=5, pady=5)
        self.password_entry.grid(row=4, column=1, padx=5, pady=5)
        self.generate_button.grid(row=5, column=1, padx=5, pady=5)
        self.separatorH.grid(row=6, column=0, columnspan=3, sticky='ew')


        # self.import_info_label.grid(row=11, column=1, padx=5, pady=5)
        # self.import_email_label.grid(row=12, column=0, padx=5, pady=5 )
        # self.import_email_entry.grid(row=12, column=1, padx=5, pady=5 )
        # self.import_name_label.grid(row=13, column=0, padx=5, pady=5 )
        # self.import_name_entry.grid(row=13, column=1, padx=5, pady=5 )
        self.keyID_label.grid(row=7, column=0, padx=5, pady=5)
        self.keyID_entry.grid(row=7, column=1, padx=5, pady=5)
        self.unlockPassword_label.grid(row=8, column=0, padx=5, pady=5)
        self.unlockPassword_entry.grid(row=8, column=1, padx=5, pady=5)
        self.export_private_button.grid(row=8, column=2, padx=5, pady=5)
        self.export_public_button.grid(row=7, column=2, padx=5, pady=5)

        self.separatorH3.grid(row=9, column=0, columnspan=20, sticky='ew')
        self.keyID_label_delete.grid(row=10, column=0, padx=5, pady=5)
        self.keyID_entry_delete.grid(row=10, column=1, padx=5, pady=5)
        self.delete_key_pair_button.grid(row=11, column=1, padx=5, pady=5)

        self.table.grid(row=1, column=5, rowspan=10, columnspan=4)
        self.my_keys.grid(row=0, column=6)
        self.separatorV2.grid(row=1, column=9, rowspan=11, sticky='ns')
        self.table_contacts.grid(row=1, column=10, rowspan=10, columnspan=4)
        self.my_contacts.grid(row=0, column=11)

        self.import_private_key_label.grid(row=11, column=6, padx=5, pady=5)
        self.for_file_label.grid(row=12, column=5, )
        self.for_file_entry.grid(row=13, column=5,)
        self.import_enter_password_label.grid(row=12, column=6)
        self.import_enter_password_entry.grid(row=13, column=6 )

        self.import_private_button.grid(row=13, column=7 )
        self.import_key_dropdown.grid(row=12, column=7)

        self.import_public_key_label.grid(row=11, column=11, padx=5, pady=5)
        # self.search_for_file_button2.grid(row=11, column=11, padx=5, pady=5)
        self.import_public_button.grid(row=13, column=11, padx=5, pady=5)

        self.send_message_label.grid(row=15, column=0, padx=5, pady=5)
        self.to_label.grid(row=16, column=0, padx=5, pady=5)
        self.to_entry.grid(row=16, column=1, padx=5, pady=5)
        self.privacy_label.grid(row=17, column=0, padx=5, pady=5)
        self.privacy_entry.grid(row=17, column=1, padx=5, pady=5)
        self.authentication_label.grid(row=18, column=0, padx=5, pady=5)
        self.authentication_entry.grid(row=18, column=1, padx=5, pady=5)
        self.compression.grid(row=19, column=0, padx=5, pady=5)
        self.radix_64.grid(row=20, column=0, padx=5, pady=5)
        self.msg_label.grid(row=21, column=0, padx=5, pady=5)
        self.msg_entry.grid(row=21, column=1, rowspan=3, columnspan=2)
        self.send_button.grid(row=24, column=1, padx=5, pady=5)

        self.receive_message_label.grid(row=15, column=7, padx=5, pady=5)
        self.receive_password_label.grid(row=16, column=7, padx=5, pady=5)
        self.receive_password_entry.grid(row=16, column=8, padx=5, pady=5)
        self.receive_info_button.grid(row=17, column=7, padx=5, pady=5)
        self.receive_info_text.grid(row=18, column=7, rowspan=3, columnspan=2)
        self.receive_save_message_label.grid(row=19, column=7, padx=5, pady=5)
        self.search_for_file_button2.grid(row=19, column=8, padx=5, pady=5)
        self.receive_save_message_button.grid(row=20, column=7, padx=5, pady=5)

        self.separatorV.grid(row=0, column=3, rowspan=20, sticky='ns')
        self.separatorH2.grid(row=14, column=0, columnspan=20, sticky='ew')

        self.right_click_menu = tk.Menu(self, tearoff=0)
        self.right_click_menu.add_command(label="View Public Key", command=self.view_public_key)
        self.right_click_menu.add_command(label="View Private Key", command=self.view_private_key)
        self.right_click_menu.add_command(label="Export Public Key", command=self.export_public_key)
        self.right_click_menu.add_command(label="Export Private Key", command=self.export_private_key)
        self.right_click_menu.add_separator()
        self.right_click_menu.add_command(label="Delete key")

    def popup(self, event):
        right_click_id = self.table.identify_row(event.y)
        if right_click_id:
            self.table.selection_set(right_click_id)
            self.right_click_menu.post(event.x_root, event.y_root)
            key_id = int(self.table.item(right_click_id)['values'][1], 16)
            key = self.key_ring.key_pairs_private.get(key_id)
            self.control_flow.set_last_key(key[0]);
        else:
            pass

    def view_public_key(self):
        new_window = ViewPublicKeyWindow(self)
        new_window.focus()

    def view_private_key(self):
        pass

    def search_for_file_path(self):
        tempdir = tkFileDialog.askopenfilename(filetypes = (("key files","*.pem"),("all files","*.*")), parent=self, initialdir="../keys/private/", title='Please select a .pem key')
        self.path_save = tempdir


    def search_for_file_path_publ(self):
        currdir = os.getcwd()
        tempdir = tkFileDialog.askdirectory(parent=self, initialdir=currdir, title='Please select a directory')
        self.path_import_public = tempdir

    def generate_key_pair(self):
        name = self.name_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        algorithm = self.algorithm_var.get()
        key_size = self.key_size_var.get()

        key_pair = PGPKeyPair(name, email, algorithm, key_size)
        key_pair.set_password(password='pas');
        key_pair.generate_key_pair(password)
        # print(key_pair.calculate_key_id())
        self.key_ring.add_key_pair(key_pair)
        self.update_table_myKeys()
        messagebox.showinfo("Key Pair Generated", "Key pair generated successfully.")

    def delete_key_pair(self):
        gg = int(self.keyID_entry.get())
        self.key_ring.key_pairs_private.remove(gg)
        self.key_ring.key_pairs_public.remove(gg)
        self.update_table_myKeys()

    def export_public_key(self):
        selected_key_pair = self.get_users_key_pair_by_id(self.keyID_entry.get())
        # password = self.unlockPassword_entry.get()
        # file_path = "../keys/" + self.email + self.name + "/private/"
        # result = selected_key_pair.export_private_key(file_path, self.keyID_entry.get())
        # messagebox.showinfo(message = result)
        # selectedKeyPairDict = self.control_flow.get_last_key()
        # key_id = str(f'{selectedKeyPairDict["key ID"]:X}')
        # selectedKeyPair = self.get_users_key_pair_by_id(selectedKeyPairDict['key ID'])
        file_path = "../keys/public/"
        selected_key_pair.export_public_key(file_path, self.keyID_entry.get())
        messagebox.showinfo(message="Public key exported successfully.")

    def export_private_key(self):
        # selectedKeyPairDict = self.control_flow.get_last_key()
        selected_key_pair = self.get_users_key_pair_by_id(self.keyID_entry.get())
        # print(selectedKeyPairDict)
        # key_id = str(f'{selectedKeyPairDict["key ID"]:X}')
        # selectedKeyPair = self.get_users_key_pair_by_id(selectedKeyPairDict['key ID'])
        # print(selectedKeyPair)
        file_path = "../keys/private/"
        # messagebox.showinfo(message="Public key exported successfully.")
        result = selected_key_pair.export_private_key(file_path, self.keyID_entry.get(), self.unlockPassword_entry.get())
        messagebox.showinfo(message=result)

    def send_message(self):
        None

    def open_message(self):
        None

    def update_table_myContacts(self):
        for row in self.table_contacts.get_children():
            self.table.delete(row)
        listPub = self.key_ring.key_pairs_private.values()
        for item in listPub:
            for i in item:
                if i['isUnlocked'] == 0:
                    self.table_contacts.insert("", tk.END, values=(i['key ID'], i['public key'], 'private key locked'))
                else:
                    self.table_contacts.insert("", tk.END, values=(i['key ID'], i['public key'], i['private key']))

    def update_table_myKeys(self):
        for row in self.table.get_children():
            self.table.delete(row)

        listPub = self.key_ring.key_pairs_private.values()
        for item in listPub:
            for i in item:
                user_id = i.get('user name', '') + " <" + i.get('user email', '') + ">"
                # k_id = i.get('key ID', '')
                # key_id = str(f'{k_id:X}')
                key_id = i.get('key ID', '')
                algorithm = i.get('algorithm', '') + "-" + str(i.get('key size', ''))
                #timestamp = datetime.fromtimestamp(i.get('timestamp', '')).strftime("%m/%d/%Y - %H:%M:%S")
                self.table.insert("", tk.END, values=(user_id, key_id, algorithm))

        for row in self.table_contacts.get_children():
            self.table_contacts.delete(row)

        listPub1 = self.key_ring.key_pairs_public.values()
        for item in listPub1:
            for i in item:
                user_id = i.get('user name', '') + " <" + i.get('user email', '') + ">"
                # k_id = i.get('key ID', '')
                # key_id = str(f'{k_id:X}')
                key_id = i.get('key ID', '')
                algorithm = i.get('algorithm', '') + "-" + str(i.get('key size', ''))
                #timestamp = datetime.fromtimestamp(i.get('timestamp', '')).strftime("%m/%d/%Y - %H:%M:%S")
                self.table_contacts.insert("", tk.END, values=(user_id, key_id, algorithm))



    def import_private_key(self):
        key_pair = PGPKeyPair(self.name_entry.get(),
                              self.email_entry.get(),
                              self.import_algorithm_var.get(),
                              None)

        key_pair.import_private_key(self.path_save, self.import_enter_password_entry.get())
        self.key_ring.add_key_pair(key_pair)
        self.update_table_myKeys()
        messagebox.showinfo(message = "Key imported")

    def import_public_key(self):
        key_pair = PGPKeyPair(self.name_entry.get(),
                              self.email_entry.get(),
                              self.import_algorithm_var.get(),
                              None)

        key_pair.import_public_key(self.path_save)
        self.key_ring.add_key_pair_public(key_pair)
        self.update_table_myKeys()
        messagebox.showinfo(message="Key imported")

    def get_users_key_pair_by_id(self, target_key_id):
        target_key_id_int = int(target_key_id)
        listPub = self.key_ring.key_pairs_private.get(target_key_id_int)
        if listPub:
            for item in listPub:
                key_id = item.get('key ID', '')
                if key_id == target_key_id_int:
                    public_key = item.get('public key', '')
                    private_key = item.get('private key', '')
                    iv_value = item.get('iv value', '')
                    algorithm = item.get('algorithm')
                    email = item.get('email')
                    pem = item.get('pem')
                    key_pair = PGPKeyPair(None, None, None, None)
                    key_pair.set_keys(public_key, private_key, algorithm, iv_value, email, pem)
                    return key_pair
            raise IndexError("Invalid key pair index")

