import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox

from PGPApplicationGUI import PGPApplicationGUI

def main():
    # root = tk.Tk()
    app = PGPApplicationGUI()
    app.mainloop()
    # root.mainloop()

if __name__ == "__main__":
    main()
