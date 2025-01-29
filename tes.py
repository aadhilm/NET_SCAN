import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import os
import platform
import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import traceroute
import psutil
from datetime import datetime
import subprocess


class LoginWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("Login")
        self.geometry("300x200")
        self.configure(bg="#1e1e2f")

        self.style = ttk.Style(self)
        self.style.configure("TLabel", font=("Helvetica", 12), foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", font=("Helvetica", 12), background="#3e3e56", foreground="#ffffff")

        ttk.Label(self, text="Username:").pack(pady=10)
        self.username_entry = ttk.Entry(self, font=("Helvetica", 12))
        self.username_entry.pack(pady=5)

        ttk.Label(self, text="Password:").pack(pady=10)
        self.password_entry = ttk.Entry(self, font=("Helvetica", 12), show="*")
        self.password_entry.pack(pady=5)

        ttk.Button(self, text="Login", command=self.authenticate).pack(pady=10)

        self.master = master
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username == "admin" and password == "password123":
            self.master.open_main_window()
            self.destroy()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def on_close(self):
        self.master.quit()
        self.destroy()


class NetworkScanner(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Futuristic Network Scanner")
        self.geometry("1200x700")
        self.configure(bg="#1e1e2f")

        self.login_window = LoginWindow(self)
        self.withdraw()

        self.scanning = False
        self.device_graph = nx.Graph()
        self.scanning_ports = False

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.setup_style()

    def setup_style(self):
        self.style.configure("TLabel", font=("Helvetica", 12), foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", font=("Helvetica", 12), background="#3e3e56", foreground="#ffffff")
        self.style.configure("TFrame", background="#1e1e2f")
        self.style.configure("TEntry", font=("Helvetica", 12), foreground="#000000")
        self.style.configure("TListbox", font=("Courier", 12), background="#1e1e2f", foreground="#00ff7f")

    def open_main_window(self):
        self.deiconify()
        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill="both", expand=True)

        control_frame = ttk.Frame(main_frame, width=300)
        control_frame.pack(side="left", fill="y", padx=10, pady=10)

        self.setup_controls(control_frame)

        output_frame = ttk.Frame(main_frame)
        output_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.setup_output(output_frame)

        system_info_frame = ttk.Frame(main_frame, padding=10, width=250)
        system_info_frame.pack(side="left", fill="y", padx=10, pady=10)

        self.setup_system_info(system_info_frame)

    def setup_controls(self, parent):
        ttk.Label(parent, text="Scan Settings", font=("Helvetica", 16, "bold")).pack(pady=10)
        ttk.Label(parent, text="Main System IP:").pack(anchor="w", pady=5)
        self.local_ip_entry = ttk.Entry(parent, state="readonly", width=20)
        self.local_ip_entry.pack(fill="x", padx=5, pady=5)
        self.fetch_main_ip()

        ttk.Label(parent, text="Network Prefix:").pack(anchor="w", pady=5)
        self.network_prefix_entry = ttk.Entry(parent, width=20)
        self.network_prefix_entry.insert(0, "192.168.1")
        self.network_prefix_entry.pack(fill="x", padx=5, pady=5)

        ttk.Label(parent, text="Ending IP Range:").pack(anchor="w", pady=5)
        self.end_ip_entry = ttk.Entry(parent, width=20)
        self.end_ip_entry.insert(0, "254")
        self.end_ip_entry.pack(fill="x", padx=5, pady=5)

        self.font_size_label = ttk.Label(parent, text="Font Size:")
        self.font_size_label.pack(anchor="w", pady=5)
        self.font_size_spinner = ttk.Spinbox(parent, from_=8, to=30, command=self.update_font_size, width=3)
        self.font_size_spinner.set(14)
        self.font_size_spinner.pack(fill="x", padx=5, pady=5)

        ttk.Button(parent, text="Start Scan", command=self.start_scan).pack(fill="x", pady=5)
        ttk.Button(parent, text="Stop Scan", command=self.stop_scan).pack(fill="x", pady=5)
        ttk.Button(parent, text="Visualize Topology", command=self.visualize_network).pack(fill="x", pady=5)
        ttk.Button(parent, text="Run Traceroute", command=self.run_traceroute).pack(fill="x", pady=5)
        ttk.Button(parent, text="Clear Output", command=self.clear_output).pack(fill="x", pady=5)

    def setup_output(self, parent):
        output_frame = ttk.LabelFrame(parent, text="Scan Output", padding=10)
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.output_text = tk.Text(output_frame, wrap="word", state="disabled", bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.output_text.pack(fill="both", expand=True)

        ttk.Label(output_frame, text="Active Devices:").pack(pady=5)
        self.device_listbox = tk.Listbox(output_frame, height=10, bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.device_listbox.pack(fill="both", padx=5, pady=5)

    def setup_system_info(self, parent):
        ttk.Label(parent, text="System Information", font=("Helvetica", 16, "bold")).pack(pady=10)

        system_info = self.get_system_info()
        for key, value in system_info.items():
            if key == "Network Interfaces":  # Add newlines for better readability
                ttk.Label(parent, text=f"{key}: {value}", font=("Helvetica", 12)).pack(anchor="w", pady=5)
                for interface in value.split(", "):
                    ttk.Label(parent, text=f"  {interface}", font=("Helvetica", 12)).pack(anchor="w", pady=2)
            else:
                ttk.Label(parent, text=f"{key}: {value}", font=("Helvetica", 12)).pack(anchor="w", pady=5)

    def get_system_info(self):
        # System information
        system_info = {
            "OS": platform.system() + " " + platform.release(),
            "Architecture": platform.architecture()[0],
            "Processor": platform.processor(),
            "Physical Cores": psutil.cpu_count(logical=False),
            "Logical Cores": psutil.cpu_count(logical=True),
            "Total RAM": f"{psutil.virtual_memory().total / (1024 ** 3):.2f} GB",
            "Available RAM": f"{psutil.virtual_memory().available / (1024 ** 3):.2f} GB",
            "Date & Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Battery information
        if hasattr(psutil, "sensors_battery"):
            battery = psutil.sensors_battery()
            if battery:
                system_info["Battery"] = f"{battery.percent}% {'(Charging)' if battery.power_plugged else '(Discharging)'}"
            else:
                system_info["Battery"] = "No battery detected"
        
        # Network interface information
        network_info = []
        interfaces = psutil.net_if_addrs()
        for iface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    network_info.append(f"{iface}: {addr.address}")
        
        system_info["Network Interfaces"] = ", ".join(network_info) if network_info else "No active network interfaces"
            
        return system_info

    def update_font_size(self):
        font_size = int(self.font_size_spinner.get())
        self.output_text.config(font=("Courier", font_size))

    def fetch_main_ip(self):
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                main_ip = s.getsockname()[0]
                self.local_ip_entry.config(state="normal")
                self.local_ip_entry.delete(0, tk.END)
                self.local_ip_entry.insert(0, main_ip)
                self.local_ip_entry.config(state="readonly")
        except Exception as e:
            self.local_ip_entry.config(state="normal")
            self.local_ip_entry.delete(0, tk.END)
            self.local_ip_entry.insert(0, "Error")
            self.local_ip_entry.config(state="readonly")
            print("Error fetching IP:", e)

    def start_scan(self):
        self.device_graph.clear()
        self.append_output("Starting network scan...\n")
        self.scanning = True
        threading.Thread(target=self.scan_network).start()

    def scan_network(self):
        network_prefix = self.network_prefix_entry.get()
        end_ip = int(self.end_ip_entry.get())

        # Initialize lists for found and not found devices
        all_ips = [f"{network_prefix}.{i}" for i in range(1, end_ip + 1)]
        found_devices = []

        for ip in all_ips:
            if not self.scanning:
                break

            response = os.system(f"ping -c 1 -W 1 {ip}")
            if response == 0:
                found_devices.append(ip)
                self.device_graph.add_node(ip)
                open_ports = self.scan_ports(ip)  # Scan for open ports here
                self.device_listbox.insert(tk.END, f"{ip} - Ports: {', '.join(map(str, open_ports))}" if open_ports else f"{ip} - No open ports")
                self.append_output(f"Device found: {ip} - Ports: {', '.join(map(str, open_ports)) if open_ports else 'No open ports'}\n")
                self.device_graph.add_edge(self.local_ip_entry.get(), ip)
            else:
                self.append_output(f"Device not found: {ip}\n")

        # Display devices that were not found
        not_found_devices = set(all_ips) - set(found_devices)
        self.append_output("\nNot Found Devices:\n")
        for device in not_found_devices:
            self.append_output(f"{device}\n")

        if not self.scanning:
            self.append_output("Scan stopped prematurely.\n")


    def scan_ports(self, ip):
        open_ports = []
        for port in range(1, 1025):  # Scan ports from 1 to 1024
            if self.check_port(ip, port):
                open_ports.append(port)
        return open_ports

    def check_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Set timeout for the connection attempt
            result = sock.connect_ex((ip, port))  # Returns 0 if connection was successful
            sock.close()
            return result == 0
        except socket.error:
            return False

    def append_output(self, message):
        self.output_text.config(state="normal")
        self.output_text.insert(tk.END, message)
        self.output_text.config(state="disabled")
        self.output_text.yview(tk.END)

    def stop_scan(self):
        self.scanning = False
        self.append_output("Scan stopped.\n")

    def visualize_network(self):
        pos = nx.spring_layout(self.device_graph)
        nx.draw(self.device_graph, pos, with_labels=True, node_size=500, node_color="skyblue", font_size=10)
        plt.show()

    def run_traceroute(self):
        destination = self.local_ip_entry.get()  # Assuming local IP is used for traceroute
        result = traceroute(destination, verbose=1)
        self.append_output("\nTraceroute Result:\n")
        for snd, rcv in result[0]:
            self.append_output(f"{snd.src} -> {rcv.src}\n")

    def clear_output(self):
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state="disabled")


if __name__ == "__main__":
    app = NetworkScanner()
    app.mainloop()
