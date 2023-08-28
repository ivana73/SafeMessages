import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

class PGPLoginGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PGP Key Manager")
        self.geometry("550x450")
        self.configure(bg="WHITE")
        self.key_ring = PGPKeyRing()
        self.email_label = tk.Label(self, text="Email:")
        self.email_entry = tk.Entry(self)
        self.email_button = tk.Button(self, text="Enter", command=self.enter)

        self.name_label.pack()
        self.name_entry.pack()
        self.email_label.pack()
        self.email_entry.pack()
        self.email_button.pack()