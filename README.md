Here's a sample `README.md` file for the Graphical Password System project:

---

# Graphical Password System

A Python application for a graphical password system using image segmentation and AES encryption, created with `Tkinter` for the GUI and `OpenCV` for image processing. Users can register by selecting an image and marking specific segments as their password. The selected segments are encrypted and stored, allowing secure login with a graphical interface.

## Features
- **User Registration and Login**: Register a new user or login with an existing user account.
- **Graphical Password**: Choose an image and select segments to set as a password.
- **AES Encryption**: Securely store password segments with AES encryption.
- **Undo Selection**: Easily undo selections for both registration and login.
- **Login Lockout**: Automatically lock login after 5 failed attempts, unlocking after 5 seconds.
- **Image Grid Customization**: Choose from grid sizes (2x2 to 5x5) during registration.
- **Data Storage**: User data is saved in `user_data.json` with AES-encrypted segments and stored paths.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/graphical-password-system.git
    cd graphical-password-system
    ```

2. **Install dependencies**:
    Make sure you have Python installed. Install the required libraries:
    ```bash
    pip install opencv-python pillow cryptography
    ```

## Usage

Run the application using the following command:
```bash
python graphical_password_system.py
```

### Registration

1. Click **Register**.
2. Enter a **username** and choose a **grid size**.
3. Select an image, which will be segmented according to the grid size.
4. Click on specific segments to set as your password.
5. Use the **Undo** button to remove the last selected segment.
6. Click **Set Password & Save** to register.

### Login

1. Click **Login**.
2. Enter your **username** and re-select the same image you used for registration.
3. Select segments that match the registered segments.
4. Click **Login**.

> **Note**: After 5 failed login attempts, the application will lock login for 5 seconds.

## File Structure
- **graphical_password_system.py**: Main application code.
- **user_data.json**: Stores user information, including encrypted segments and image paths.

## Security
This application encrypts selected segments with AES encryption. For each user, a unique 256-bit key is generated and stored as a base64-encoded string in `user_data.json`.

## Dependencies
- `OpenCV`: For image processing and segmentation.
- `Tkinter`: For GUI.
- `Pillow`: For image display in the GUI.
- `Cryptography`: For AES encryption and decryption.

## Future Enhancements
- Enhance user experience with improved feedback on selections.
- Add more robust encryption and store encryption keys securely.
- Add additional feedback for unsuccessful login attempts.

---

