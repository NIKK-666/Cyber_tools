import re
import tkinter as tk
from tkinter import messagebox

class PasswordAnalyzer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Strength Analyzer")

        # GUI components
        self.label = tk.Label(self.root, text="Enter your password:", font=("Arial", 14))
        self.label.pack(pady=10)

        self.password_entry = tk.Entry(self.root, show="*", font=("Arial", 14), width=30)
        self.password_entry.pack(pady=10)

        self.analyze_button = tk.Button(
            self.root, text="Analyze Password", command=self.analyze_password, font=("Arial", 12)
        )
        self.analyze_button.pack(pady=10)

        self.result_label = tk.Label(self.root, text="", font=("Arial", 12), wraplength=400, justify="left")
        self.result_label.pack(pady=10)

    def analyze_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password to analyze.")
            return

        strength, recommendations = self.evaluate_password(password)
        result_text = f"Password Strength: {strength}\n\nRecommendations:\n" + "\n".join(recommendations)
        self.result_label.config(text=result_text)

    def evaluate_password(self, password):
        # Initialize the score and feedback list
        score = 0
        feedback = []

        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Increase the length to at least 12 characters.")

        # Lowercase letters check
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add at least one lowercase letter.")

        # Uppercase letters check
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add at least one uppercase letter.")

        # Digits check
        if re.search(r"[0-9]", password):
            score += 1
        else:
            feedback.append("Add at least one digit.")

        # Special characters check
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            feedback.append("Add at least one special character (!@#$%^&* etc.).")

        # Consecutive or repetitive characters check
        if re.search(r"(.)\1\1", password):
            feedback.append("Avoid consecutive or repetitive characters (e.g., 'aaa').")

        # Common patterns check
        common_patterns = ["password", "123456", "qwerty", "admin", "iloveyou"]
        if any(pattern in password.lower() for pattern in common_patterns):
            feedback.append("Avoid common patterns like 'password', '123456', or 'qwerty'.")

        # Determine strength based on score
        if score >= 5:
            strength = "Strong"
        elif 3 <= score < 5:
            strength = "Moderate"
        else:
            strength = "Weak"

        return strength, feedback

    def run(self):
        self.root.geometry("500x300")
        self.root.mainloop()


if __name__ == "__main__":
    analyzer = PasswordAnalyzer()
    analyzer.run()
