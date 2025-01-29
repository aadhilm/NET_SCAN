import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import threading
import os
import networkx as nx


class AdminModule:
    def __init__(self, master):
        self.master = master

    def display(self, parent):
        ttk.Label(parent, text="Admin Module", font=("Helvetica", 16, "bold")).pack(pady=10)

        ttk.Button(parent, text="Advanced Network Config", command=self.configure_network).pack(fill="x", pady=5)
        ttk.Button(parent, text="View Logs", command=self.view_logs).pack(fill="x", pady=5)
        ttk.Button(parent, text="Run Diagnostics", command=self.run_diagnostics).pack(fill="x", pady=5)

    def configure_network(self):
        messagebox.showinfo("Admin", "Network configuration tool coming soon!")

    def view_logs(self):
        messagebox.showinfo("Admin", "Log viewer coming soon!")

    def run_diagnostics(self):
        messagebox.showinfo("Admin", "System diagnostics tool coming soon!")


class UserModule:
    def __init__(self, master):
        self.master = master

    def display(self, parent):
        ttk.Label(parent, text="User Module", font=("Helvetica", 16, "bold")).pack(pady=10)

        ttk.Button(parent, text="Scan Network", command=self.master.start_scan).pack(fill="x", pady=5)
        ttk.Button(parent, text="View System Info", command=self.show_system_info).pack(fill="x", pady=5)

    def show_system_info(self):
        system_info = {
            "OS": os.name,
            "Network Name": os.getenv("COMPUTERNAME", "Unknown"),
        }
        info_message = "\n".join(f"{key}: {value}" for key, value in system_info.items())
        messagebox.showinfo("System Info", info_message)


class LoginWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("Login")
        self.geometry("300x250")
        self.configure(bg="#1e1e2f")

        ttk.Label(self, text="Username:").pack(pady=10)
        self.username_entry = ttk.Entry(self, font=("Helvetica", 12))
        self.username_entry.pack(pady=5)

        ttk.Label(self, text="Password:").pack(pady=10)
        self.password_entry = ttk.Entry(self, font=("Helvetica", 12), show="*")
        self.password_entry.pack(pady=5)

        ttk.Button(self, text="Login", command=self.authenticate).pack(pady=10)
        ttk.Button(self, text="Register", command=self.open_register_window).pack(pady=5)

        self.master = master

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            self.master.authenticate_user(username)
            self.master.open_main_window()
            self.destroy()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def open_register_window(self):
        RegisterWindow(self.master)


class RegisterWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("Register")
        self.geometry("300x300")
        self.configure(bg="#1e1e2f")

        ttk.Label(self, text="Username:").pack(pady=10)
        self.username_entry = ttk.Entry(self, font=("Helvetica", 12))
        self.username_entry.pack(pady=5)

        ttk.Label(self, text="Password:").pack(pady=10)
        self.password_entry = ttk.Entry(self, font=("Helvetica", 12), show="*")
        self.password_entry.pack(pady=5)

        ttk.Label(self, text="Confirm Password:").pack(pady=10)
        self.confirm_password_entry = ttk.Entry(self, font=("Helvetica", 12), show="*")
        self.confirm_password_entry.pack(pady=5)

        ttk.Button(self, text="Register", command=self.register_user).pack(pady=10)

    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "All fields are required")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            messagebox.showinfo("Success", "Registration successful!")
            self.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")
        finally:
            conn.close()


class NetworkScanner(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Futuristic Network Scanner")
        self.geometry("1200x700")
        self.configure(bg="#1e1e2f")

        self.initialize_database()

        self.login_window = LoginWindow(self)
        self.withdraw()  # Start with the login screen

        self.admin_module = AdminModule(self)
        self.user_module = UserModule(self)
        self.user_role = None  # Set after login

        self.scanning = False
        self.device_graph = nx.Graph()

    def initialize_database(self):
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)
        conn.commit()
        conn.close()

    def authenticate_user(self, username):
        self.user_role = "Admin" if username == "admin" else "User"

    def open_main_window(self):
        self.deiconify()  # Show the main application window
        self.setup_ui()

    def logout(self):
        self.withdraw()  # Hide the main application window
        self.login_window = LoginWindow(self)  # Reopen the login window

    def setup_ui(self):
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill="both", expand=True)

        control_frame = ttk.Frame(main_frame, width=300)
        control_frame.pack(side="left", fill="y", padx=10, pady=10)

        self.setup_controls(control_frame)

        output_frame = ttk.Frame(main_frame)
        output_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.setup_output(output_frame)

        role_frame = ttk.Frame(main_frame, padding=10, width=250)
        role_frame.pack(side="left", fill="y", padx=10, pady=10)

        if self.user_role == "Admin":
            self.admin_module.display(role_frame)
        elif self.user_role == "User":
            self.user_module.display(role_frame)

        # Add logout button
        ttk.Button(main_frame, text="Logout", command=self.logout).pack(side="bottom", pady=10)

    def setup_controls(self, parent):
        ttk.Label(parent, text="Scan Settings", font=("Helvetica", 16, "bold")).pack(pady=10)
        ttk.Label(parent, text="Network Prefix:").pack(anchor="w", pady=5)
        self.network_prefix_entry = ttk.Entry(parent, width=20)
        self.network_prefix_entry.insert(0, "192.168.1")
        self.network_prefix_entry.pack(fill="x", padx=5, pady=5)

        ttk.Label(parent, text="Ending IP Range:").pack(anchor="w", pady=5)
        self.end_ip_entry = ttk.Entry(parent, width=20)
        self.end_ip_entry.insert(0, "254")
        self.end_ip_entry.pack(fill="x", padx=5, pady=5)

        ttk.Button(parent, text="Start Scan", command=self.start_scan).pack(fill="x", pady=5)
        ttk.Button(parent, text="Stop Scan", command=self.stop_scan).pack(fill="x", pady=5)

    def setup_output(self, parent):
        output_frame = ttk.LabelFrame(parent, text="Scan Output", padding=10)
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.output_text = tk.Text(output_frame, wrap="word", state="disabled", bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.output_text.pack(fill="both", expand=True)

    def start_scan(self):
        self.scanning = True
        self.append_output("Starting network scan...\n")
        threading.Thread(target=self.scan_network).start()

    def scan_network(self):
        network_prefix = self.network_prefix_entry.get()
        end_ip = int(self.end_ip_entry.get())
        all_ips = [f"{network_prefix}.{i}" for i in range(1, end_ip + 1)]

        for ip in all_ips:
            if not self.scanning:
                break

            response = os.system(f"ping -c 1 -W 1 {ip}")
            if response == 0:
                self.device_graph.add_node(ip)
                self.append_output(f"Device found: {ip}\n")

        self.scanning = False
        self.append_output("Scan complete!\n")

    def stop_scan(self):
        self.scanning = False
        self.append_output("Scan stopped by user.\n")

    def append_output(self, text):
        self.output_text.config(state="normal")
        self.output_text.insert("end", text)
        self.output_text.config(state="disabled")
        self.output_text.see("end")


if __name__ == "__main__":
    app = NetworkScanner()
    app.mainloop()
