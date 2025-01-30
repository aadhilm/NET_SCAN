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

        # Styling for Login
        self.style = ttk.Style(self)
        self.style.configure("TLabel", font=("Helvetica", 12), foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", font=("Helvetica", 12), background="#3e3e56", foreground="#ffffff")

        # User interface elements for login
        ttk.Label(self, text="Username:", font=("Helvetica", 12)).pack(pady=10)
        self.username_entry = ttk.Entry(self, font=("Helvetica", 12))
        self.username_entry.pack(pady=5)

        ttk.Label(self, text="Password:", font=("Helvetica", 12)).pack(pady=10)
        self.password_entry = ttk.Entry(self, font=("Helvetica", 12), show="*")
        self.password_entry.pack(pady=5)

        # Login button
        ttk.Button(self, text="Login", command=self.authenticate).pack(pady=10)

        # Remember this window as the master window
        self.master = master
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def authenticate(self):
        """Check if the entered credentials are correct."""
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Hardcoded credentials (could be improved for real use cases)
        if username == "admin" and password == "password123":
            self.master.open_main_window()  # Open main window if authenticated
            self.destroy()  # Close the login window
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def on_close(self):
        """Handle window close event."""
        self.master.quit()
        self.destroy()


class NetworkScanner(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Futuristic Network Scanner")
        self.geometry("1200x700")
        self.configure(bg="#1e1e2f")

        # Initializing login screen
        self.login_window = LoginWindow(self)
        self.withdraw()  # Hide the main window until login is successful

        # Flags
        self.scanning = False
        self.device_graph = nx.Graph()

        # Styling
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.setup_style()

    def setup_style(self):
        """Setup the modern style for widgets."""
        self.style.configure("TLabel", font=("Helvetica", 12), foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", font=("Helvetica", 12), background="#3e3e56", foreground="#ffffff")
        self.style.configure("TFrame", background="#1e1e2f")
        self.style.configure("TEntry", font=("Helvetica", 12), foreground="#000000")
        self.style.configure("TListbox", font=("Courier", 12), background="#1e1e2f", foreground="#00ff7f")

    def open_main_window(self):
        """Open the main network scanner window after successful login."""
        self.deiconify()  # Show the main window
        self.setup_ui()

    def setup_ui(self):
        """Setup the main UI with all components in one screen."""
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill="both", expand=True)

        # Left panel: Controls and scan settings
        control_frame = ttk.Frame(main_frame, width=300)
        control_frame.pack(side="left", fill="y", padx=10, pady=10)

        self.setup_controls(control_frame)

        # Center panel: Output and visualization
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.setup_output(output_frame)

        # Right panel: System Info
        system_info_frame = ttk.Frame(main_frame, padding=10, width=250)
        system_info_frame.pack(side="right", fill="y", padx=10, pady=10)

        self.setup_system_info(system_info_frame)  # Display system info on the right



    def setup_controls(self, parent):
        """Setup the control panel on the left side."""
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
        ttk.Button(parent, text="Advanced Visualize Topology", command=self.advanced_visualize_network).pack(fill="x", pady=5)
        ttk.Button(parent, text="Run Traceroute", command=self.run_traceroute).pack(fill="x", pady=5)
        ttk.Button(parent, text="Clear Output", command=self.clear_output).pack(fill="x", pady=5)

    def setup_output(self, parent):
        """Setup the output and visualization section."""
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
        """Update the font size based on the spinner value."""
        font_size = int(self.font_size_spinner.get())
        self.output_text.config(font=("Courier", font_size))

    def fetch_main_ip(self):
        """Fetch and display the local system's IP address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                main_ip = s.getsockname()[0]
                self.local_ip_entry.config(state="normal")
                self.local_ip_entry.delete(0, tk.END)
                self.local_ip_entry.insert(0, main_ip)
                self.local_ip_entry.config(state="readonly")
        except Exception as e:
            self.append_output(f"Error fetching IP: {e}")

    def start_scan(self):
        """Start the network scan."""
        if self.scanning:
            return
        self.scanning = True
        network_prefix = self.network_prefix_entry.get()
        end_ip = int(self.end_ip_entry.get())
        self.append_output(f"Starting scan on {network_prefix}.1-{network_prefix}.{end_ip}...\n")
        threading.Thread(target=self.scan_network, args=(network_prefix, end_ip)).start()

    def scan_network(self, prefix, end_ip):
        """Perform the network scan."""
        self.device_graph.clear()  # Clear previous scan results
        self.device_graph.add_node("Router")  # Add central router node

        try:
            for i in range(1, end_ip + 1):
                target_ip = f"{prefix}.{i}"
                if self.ping_device(target_ip):
                    self.append_output(f"{target_ip} is active\n")
                    self.device_listbox.insert(tk.END, f"{target_ip} is active")
                    self.device_graph.add_node(target_ip)  # Add active device to graph
                    self.device_graph.add_edge("Router", target_ip)  # Link to router
                else:
                    self.append_output(f"{target_ip} is inactive\n")
        except Exception as e:
            self.append_output(f"Error during scan: {e}")
        finally:
            self.scanning = False
            self.append_output("\nScan completed.\n")


    def ping_device(self, ip):
        """Ping a device to check if it is active."""
        param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
        command = f"ping {param} {ip}"
        return os.system(command) == 0
    
    def append_output(self, text):
        self.output_text.config(state="normal")
        self.output_text.insert(tk.END, text)
        self.output_text.config(state="disabled")
        self.output_text.yview(tk.END)

    def stop_scan(self):
        """Stop the scan."""
        self.scanning = False
        self.append_output("Scan stopped\n")

    def visualize_network(self):
        """Display network topology graph."""
        if not hasattr(self, "device_graph") or self.device_graph.number_of_nodes() == 0:
            self.append_output("No network data available for visualization.\n")
            return

        plt.figure(figsize=(10, 10))
        nx.draw(self.device_graph, with_labels=True, node_color="skyblue", node_size=3000, font_size=10, font_weight="bold")
        plt.title("Network Topology")
        plt.show()


    def advanced_visualize_network(self):
        """Launch EtherApe for network visualization."""
        self.append_output("Launching EtherApe for network visualization...\n")
        try:
            # Launch EtherApe with elevated privileges
            if os.system("which etherape > /dev/null") == 0:
                os.system("sudo etherape &")
            else:
                self.append_output("Error: EtherApe is not installed on your system.\n")
        except Exception as e:
            self.append_output(f"Error launching EtherApe: {e}\n")

    def run_traceroute(self):
        """Run traceroute to a specific destination."""
        destination = self.network_prefix_entry.get()
        self.append_output(f"Running traceroute to {destination}...\n")
        res, _ = traceroute(destination, maxttl=20)
        self.append_output(str(res))

    def append_output(self, message):
        """Append a message to the output box."""
        self.output_text.config(state="normal")
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state="disabled")

    def clear_output(self):
        """Clear the output box."""
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")


if __name__ == "__main__":
    app = NetworkScanner()
    app.mainloop()
