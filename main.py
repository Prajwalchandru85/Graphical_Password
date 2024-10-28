import os
import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import json
import time

# Function to encrypt data
def encrypt_data(data, key):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    iv = os.urandom(16)  # Generate random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return b64encode(iv + encrypted_data).decode('utf-8')  # Return Base64 encoded data

# Function to decrypt data
def decrypt_data(encrypted_data, key):
    encrypted_data = b64decode(encrypted_data)
    iv = encrypted_data[:16]  # Extract the IV
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Function to segment the image into a grid
def segment_image(image_path, grid_size):
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError(f"Could not read image from path: {image_path}")
    
    image_height, image_width, _ = image.shape
    grid_h, grid_w = image_height // grid_size, image_width // grid_size

    segments = []
    for row in range(grid_size):
        for col in range(grid_size):
            segment = image[row * grid_h:(row + 1) * grid_h, col * grid_w:(col + 1) * grid_w]
            segments.append(segment)

    return segments, grid_h, grid_w  # Return segments and grid size

# Main application class
class GraphicalPasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Graphical Password System")
        
        self.user_data_file = "user_data.json"
        self.load_user_data()
        self.failed_attempts = 0  # Initialize failed attempts counter
        self.locked = False  # Flag to check if login is locked

        # Initialize main UI
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(pady=20)

        self.register_button = tk.Button(self.main_frame, text="Register", command=self.open_register_window)
        self.register_button.pack(pady=10)

        self.login_button = tk.Button(self.main_frame, text="Login", command=self.open_login_window)
        self.login_button.pack(pady=10)

    def load_user_data(self):
        # Load existing user data from the JSON file
        if os.path.exists(self.user_data_file):
            with open(self.user_data_file, "r") as f:
                self.user_data = json.load(f)
        else:
            self.user_data = {}

    def save_user_data(self):
        # Save user data to the JSON file
        with open(self.user_data_file, "w") as f:
            json.dump(self.user_data, f)

    def open_register_window(self):
        self.main_frame.pack_forget()
        self.register_frame = tk.Frame(self.root)
        self.register_frame.pack(pady=20)

        tk.Label(self.register_frame, text="Username:").pack()
        self.username_entry = tk.Entry(self.register_frame)
        self.username_entry.pack(pady=5)

        tk.Label(self.register_frame, text="Choose Grid Size:").pack()
        self.grid_size_var = tk.IntVar(value=4)
        grid_options = [2, 3, 4, 5]
        for size in grid_options:
            tk.Radiobutton(self.register_frame, text=f"{size}x{size}", variable=self.grid_size_var, value=size).pack()

        self.choose_image_button = tk.Button(self.register_frame, text="Choose Image", command=self.choose_image)
        self.choose_image_button.pack(pady=10)

        # Undo Button
        self.undo_button = tk.Button(self.register_frame, text="Undo", command=self.undo_selection)
        self.undo_button.pack(pady=5)

        self.save_button = tk.Button(self.register_frame, text="Set Password & Save", command=self.save_password)
        self.save_button.pack(pady=10)

        self.back_button = tk.Button(self.register_frame, text="Back to Main Menu", command=self.go_back)
        self.back_button.pack(pady=10)

    def choose_image(self):
        self.image_path = filedialog.askopenfilename(title="Select an image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not self.image_path:
            messagebox.showwarning("Warning", "No image selected!")
            return
        
        try:
            self.grid_size = self.grid_size_var.get()
            self.segments, self.segment_height, self.segment_width = segment_image(self.image_path, self.grid_size)
            self.selected_segments = []  # Reset selected segments for new image
            self.display_image(self.image_path)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def display_image(self, image_path):
        self.canvas = tk.Canvas(self.register_frame, width=400, height=400)
        self.canvas.pack()
        self.image = Image.open(image_path)
        self.photo = ImageTk.PhotoImage(self.image)
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.photo)

        # Bind click events to the image
        self.canvas.bind("<Button-1>", self.on_click)

    def on_click(self, event):
        x, y = event.x, event.y
        col = x // self.segment_width
        row = y // self.segment_height
        if (row, col) not in self.selected_segments:
            self.selected_segments.append((row, col))
            self.highlight_segments()

    def highlight_segments(self):
        self.canvas.delete("highlight")
        for (row, col) in self.selected_segments:
            x1 = col * self.segment_width
            y1 = row * self.segment_height
            x2 = x1 + self.segment_width
            y2 = y1 + self.segment_height
            self.canvas.create_rectangle(x1, y1, x2, y2, outline="red", width=4, tags="highlight")

    # Undo selection method
    def undo_selection(self):
        if self.selected_segments:
            self.selected_segments.pop()  # Remove the last selected segment
            self.highlight_segments()  # Update the canvas to reflect the change

    def save_password(self):
        username = self.username_entry.get()
        if not username or not self.selected_segments:
            messagebox.showwarning("Warning", "Please enter a username and select segments.")
            return

        if username in self.user_data:
            messagebox.showwarning("Warning", "Username already exists! Choose a different one.")
            return
        
        # Convert selected segments to a string
        segments_str = str(self.selected_segments).encode('utf-8')
        
        # Generate a unique encryption key for the user
        secret_key = os.urandom(32)
        
        # Encrypt the selected segments
        encrypted_segments = encrypt_data(segments_str, secret_key)
        
        # Save user data with the grid size
        self.user_data[username] = {
            'image_path': self.image_path,
            'grid_size': self.grid_size,
            'encrypted_segments': encrypted_segments,
            'secret_key': b64encode(secret_key).decode('utf-8')  # Save the key as base64 string
        }

        # Save to file
        self.save_user_data()

        messagebox.showinfo("Success", "Password saved successfully!")

    def open_login_window(self):
        self.main_frame.pack_forget()
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(pady=20)

        tk.Label(self.login_frame, text="Username:").pack()
        self.login_username_entry = tk.Entry(self.login_frame)
        self.login_username_entry.pack(pady=5)

        tk.Label(self.login_frame, text="Choose Image for Login:").pack()
        self.login_image_button = tk.Button(self.login_frame, text="Choose Image", command=self.load_login_image)
        self.login_image_button.pack(pady=10)

        # Undo Button
        self.login_undo_button = tk.Button(self.login_frame, text="Undo", command=self.undo_login_selection)
        self.login_undo_button.pack(pady=5)

        self.login_button = tk.Button(self.login_frame, text="Login", command=self.check_password)
        self.login_button.pack(pady=10)

        self.back_button = tk.Button(self.login_frame, text="Back to Main Menu", command=self.go_back)
        self.back_button.pack(pady=10)

    def load_login_image(self):
        self.login_image_path = filedialog.askopenfilename(title="Select your image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not self.login_image_path:
            messagebox.showwarning("Warning", "No image selected!")
            return
        
        try:
            username = self.login_username_entry.get()
            if username not in self.user_data:
                messagebox.showerror("Error", "Username not found!")
                return

            # Retrieve the registered image path and grid size
            self.grid_size = self.user_data[username]['grid_size']
            self.segments, self.segment_height, self.segment_width = segment_image(self.login_image_path, self.grid_size)
            self.selected_login_segments = []  # Reset login selections
            self.display_login_image(self.login_image_path)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def display_login_image(self, image_path):
        self.login_canvas = tk.Canvas(self.login_frame, width=400, height=400)
        self.login_canvas.pack()
        self.login_image = Image.open(image_path)
        self.login_photo = ImageTk.PhotoImage(self.login_image)
        self.login_canvas.create_image(0, 0, anchor=tk.NW, image=self.login_photo)

        # Bind click events to the login image
        self.login_canvas.bind("<Button-1>", self.on_login_click)

    def on_login_click(self, event):
        x, y = event.x, event.y
        col = x // self.segment_width
        row = y // self.segment_height
        if (row, col) not in self.selected_login_segments:
            self.selected_login_segments.append((row, col))
            self.highlight_login_segments()

    def highlight_login_segments(self):
        self.login_canvas.delete("highlight")
        for (row, col) in self.selected_login_segments:
            x1 = col * self.segment_width
            y1 = row * self.segment_height
            x2 = x1 + self.segment_width
            y2 = y1 + self.segment_height
            self.login_canvas.create_rectangle(x1, y1, x2, y2, outline="green", width=4, tags="highlight")

    # Undo login selection method
    def undo_login_selection(self):
        if self.selected_login_segments:
            self.selected_login_segments.pop()  # Remove the last selected segment
            self.highlight_login_segments()  # Update the canvas to reflect the change

    def check_password(self):
        username = self.login_username_entry.get()

        if self.locked:
            messagebox.showwarning("Login Locked", "Too many failed attempts! Please wait before retrying.")
            return
        
        if username not in self.user_data:
            messagebox.showerror("Error", "Username not found!")
            return

        user_info = self.user_data[username]

        if self.login_image_path != user_info['image_path']:
            messagebox.showerror("Error", "Invalid credentials")
            return
        
        # Retrieve the encrypted segments and secret key
        encrypted_segments = user_info['encrypted_segments']
        secret_key = b64decode(user_info['secret_key'])
        
        # Convert selected login segments to string
        login_segments_str = str(self.selected_login_segments).encode('utf-8')

        # Decrypt registered segments
        registered_segments = decrypt_data(encrypted_segments.encode('utf-8'), secret_key)
        
        if login_segments_str == registered_segments:
            messagebox.showinfo("Success", f"Login successful!\nHello {username}")
            self.failed_attempts = 0  # Reset failed attempts after successful login
        else:
            self.failed_attempts += 1
            messagebox.showerror("Error", "Incorrect password!")
            
            if self.failed_attempts >= 5:
                self.lock_login()

    def lock_login(self):
        messagebox.showwarning("Login Locked", "Too many failed attempts! Please wait 5 seconds.")
        self.locked = True
        self.root.after(5000, self.unlock_login)  # Lock login for 5 seconds

    def unlock_login(self):
        self.locked = False
        self.failed_attempts = 0
        messagebox.showinfo("Unlocked", "You can try logging in again.")

    def go_back(self):
        # Go back to main frame
        if hasattr(self, 'register_frame'):
            self.register_frame.pack_forget()
        if hasattr(self, 'login_frame'):
            self.login_frame.pack_forget()
        self.main_frame.pack(pady=20)

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = GraphicalPasswordApp(root)
    root.mainloop()
