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
import requests
import whois
import ssl
import paramiko  # Import paramiko for SSH connections


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
        self.auto_scanning = False
        self.auto_scan_timer = None  # Store the timer object
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

        ttk.Label(parent, text="IP Range (e.g., 3-8):").pack(anchor="w", pady=5)
        self.ip_range_entry = ttk.Entry(parent, width=20)
        self.ip_range_entry.insert(0, "1-254")
        self.ip_range_entry.pack(fill="x", padx=5, pady=5)

        ttk.Label(parent, text="Traceroute Target:").pack(anchor="w", pady=5)
        self.traceroute_entry = ttk.Entry(parent, width=20)
        self.traceroute_entry.pack(fill="x", padx=5, pady=5)

        ttk.Button(parent, text="Traceroute", command=self.traceroute_device).pack(fill="x", pady=5)

        self.font_size_label = ttk.Label(parent, text="Font Size:")
        self.font_size_label.pack(anchor="w", pady=5)
        self.font_size_spinner = ttk.Spinbox(parent, from_=8, to=30, command=self.update_font_size, width=3)
        self.font_size_spinner.set(14)
        self.font_size_spinner.pack(fill="x", padx=5, pady=5)

        ttk.Button(parent, text="Start Scan", command=self.start_scan).pack(fill="x", pady=5)
        ttk.Button(parent, text="Stop Scan", command=self.stop_scan).pack(fill="x", pady=5)
        ttk.Button(parent, text="Scan Ports (Selected Device)", command=self.scan_ports).pack(fill="x", pady=5)
        ttk.Button(parent, text="Auto Scan", command=self.toggle_auto_scan).pack(fill="x", pady=5)
        ttk.Button(parent, text="Visualize Topology", command=self.visualize_network).pack(fill="x", pady=5)
        ttk.Button(parent, text="Advanced Visualize Topology", command=self.advanced_visualize_network).pack(fill="x", pady=5)
        ttk.Button(parent, text="Web Scan", command=self.open_web_scanner).pack(fill="x", pady=5)
        ttk.Button(parent, text="SSH Connect", command=self.open_ssh_connection).pack(fill="x", pady=5)
        ttk.Button(parent, text="Export Results", command=self.export_results).pack(fill="x", pady=5)
        ttk.Button(parent, text="Clear Output", command=self.clear_all).pack(fill="x", pady=5)

    def open_ssh_connection(self):
        """Open the SSH connection window."""
        SSHConnectionWindow(self)

    def traceroute_device(self):
        """Perform a traceroute to the specified target."""
        target = self.traceroute_entry.get()
        if not target:
            self.append_output("No target specified for traceroute.\n")
            return

        self.append_output(f"Performing traceroute to {target}...\n")

        # Function to perform traceroute in a separate thread
        def perform_traceroute():
            try:
                # Perform traceroute using scapy
                result, _ = traceroute(target, maxttl=30, verbose=0)  # Set maxttl to limit the number of hops
                self.append_output("Traceroute Results:\n")

                for sent, received in result:
                    if received:
                        self.append_output(f"Hop {sent.ttl}: {received.src}\n")
                    else:
                        self.append_output(f"Hop {sent.ttl}: *\n")

            except Exception as e:
                self.append_output(f"Error during traceroute: {e}\n")

        # Run traceroute in a separate thread to avoid freezing the GUI
        threading.Thread(target=perform_traceroute).start()

    def validate_ip_range(self, value):
        """Validate that the ending IP range is between 0 and 254."""
        try:
            if value == "":
                return True  # Allow empty field
            num = int(value)
            return 0 <= num <= 254
        except ValueError:
            return False

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
        ip_range = self.ip_range_entry.get()
        try:
            start_ip, end_ip = map(int, ip_range.split("-"))
            if start_ip > end_ip or start_ip < 1 or end_ip > 254:
                raise ValueError("Invalid IP range")
            self.append_output(f"Starting scan on {network_prefix}.{start_ip} to {network_prefix}.{end_ip}...\n")
            threading.Thread(target=self.scan_network, args=(network_prefix, start_ip, end_ip)).start()
        except ValueError:
            self.append_output("Invalid IP range. Please enter in the format: start-end (e.g., 3-8).\n")


    def scan_network(self, prefix, start_ip, end_ip):
        """Perform the network scan."""
        self.device_graph.clear()
        self.device_graph.add_node("Router")

        try:
            for i in range(start_ip, end_ip + 1):
                if not self.auto_scanning and not self.scanning:
                    break
                target_ip = f"{prefix}.{i}"
                if self.ping_device(target_ip):
                    self.append_output(f"{target_ip} is active\n")
                    self.device_listbox.insert(tk.END, f"{target_ip} is active")
                    self.device_graph.add_node(target_ip)
                    self.device_graph.add_edge("Router", target_ip)
                else:
                    self.append_output(f"{target_ip} is inactive\n")
        except Exception as e:
            self.append_output(f"Error during scan: {e}")
        finally:
            self.scanning = False
            self.append_output("\nScan completed.\n")

            if self.auto_scanning:
                self.append_output("Auto-scanning will resume in 10 seconds...\n")
                self.auto_scan_timer = threading.Timer(10, self.start_scan)
                self.auto_scan_timer.start()


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

    def scan_ports(self):
        """Scan open ports on the selected active device."""
        selected_device = self.device_listbox.get(tk.ACTIVE)  # Get the selected device from the listbox
        if not selected_device:
            self.append_output("No device selected for port scanning.\n")
            return

        # Extract the IP address from the selected device string
        try:
            ip_address = selected_device.split()[0]  # Assuming the IP is the first part of the string
        except IndexError:
            self.append_output("Invalid device selection format.\n")
            return

        self.append_output(f"Scanning open ports on {ip_address}...\n")

        # Function to perform port scan in a separate thread
        def port_scan():
            open_ports = []
            for port in range(1, 1025):  # Scan common ports (1 to 1024)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)  # Set timeout to 0.5 seconds
                    result = sock.connect_ex((ip_address, port))  # Try connecting to the port
                    if result == 0:  # If successful, add port to open_ports list
                        open_ports.append(port)

            # Show the result in the output box
            if open_ports:
                self.append_output(f"Open ports on {ip_address}: {', '.join(map(str, open_ports))}\n")
            else:
                self.append_output(f"No open ports found on {ip_address}.\n")

        # Run port scanning in a separate thread to avoid freezing the GUI
        threading.Thread(target=port_scan).start()

    def traceroute_device(self):
        """Perform a traceroute to the selected device."""
        selected_device = self.device_listbox.get(tk.ACTIVE)  # Get the selected device from the listbox
        if not selected_device:
            self.append_output("No device selected for traceroute.\n")
            return

        # Extract the IP address from the selected device string
        try:
            ip_address = selected_device.split()[0]  # Assuming the IP is the first part of the string
        except IndexError:
            self.append_output("Invalid device selection format.\n")
            return

        self.append_output(f"Performing traceroute to {ip_address}...\n")

        # Function to perform traceroute in a separate thread
        def perform_traceroute():
            try:
                # Perform traceroute using scapy
                result, _ = traceroute(ip_address, maxttl=30, verbose=0)  # Set maxttl to limit the number of hops
                self.append_output("Traceroute Results:\n")

                for sent, received in result:
                    if received:
                        self.append_output(f"Hop {sent.ttl}: {received.src}\n")
                    else:
                        self.append_output(f"Hop {sent.ttl}: *\n")

            except Exception as e:
                self.append_output(f"Error during traceroute: {e}\n")

        # Run traceroute in a separate thread to avoid freezing the GUI
        threading.Thread(target=perform_traceroute).start()

    def toggle_auto_scan(self):
        """Toggle auto-scan on or off."""
        if self.auto_scanning:
            self.auto_scanning = False
            if self.auto_scan_timer:
                self.auto_scan_timer.cancel()  # Cancel the scheduled timer
                self.auto_scan_timer = None
            self.append_output("Auto-scan stopped\n")
        else:
            self.auto_scanning = True
            self.append_output("Auto-scan started\n")
            self.start_scan()

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

    def export_results(self):
        """Export scan output and active devices to a text file."""
        filename = f"network_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w") as file:
                file.write("Scan Output:\n")
                file.write(self.output_text.get("1.0", tk.END))
                file.write("\nActive Devices:\n")
                for i in range(self.device_listbox.size()):
                    file.write(self.device_listbox.get(i) + "\n")

            messagebox.showinfo("Export Successful", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export results: {e}")


    def clear_all(self):
        """Clear both the active devices list and the scan output."""
        # Clear the active devices list
        self.device_listbox.delete(0, tk.END)

        # Clear the scan output
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")

        self.append_output("All data cleared.\n")

    def open_web_scanner(self):
        WebScannerWindow(self)

class WebScannerWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("Network & Web Scanner")
        self.geometry("700x500")
        self.configure(bg="#1e1e2f")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TLabel", foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", background="#3e3e56", foreground="#ffffff")

        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Enter Website URL (e.g., example.com):").pack(pady=5)
        self.url_entry = ttk.Entry(self, width=50)
        self.url_entry.pack(pady=5)

        ttk.Button(self, text="Scan Website", command=self.scan_website).pack(pady=5)
        ttk.Button(self, text="Check Open Ports", command=self.check_open_ports).pack(pady=5)
        ttk.Button(self, text="SSL Certificate Info", command=self.ssl_certificate_info).pack(pady=5)
        ttk.Button(self, text="Track Route", command=self.track_route).pack(pady=5)

        self.output_text = tk.Text(self, wrap="word", height=18, bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.output_text.pack(pady=5, fill="both", expand=True)

    def scan_website(self):
        url = self.url_entry.get()
        self.output_text.insert(tk.END, f"Scanning website {url}...\n")
        try:
            domain_info = whois.whois(url)
            self.output_text.insert(tk.END, f"Domain Info:\n{domain_info}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error scanning website: {e}\n")

    def check_open_ports(self):
        url = self.url_entry.get()
        self.output_text.insert(tk.END, f"Checking open ports for {url}...\n")
        try:
            ip = socket.gethostbyname(url)
            open_ports = []
            for port in range(1, 1025):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)

            if open_ports:
                self.output_text.insert(tk.END, f"Open ports: {open_ports}\n")
            else:
                self.output_text.insert(tk.END, "No open ports found in range 1-1024.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error checking ports: {e}\n")

    def ssl_certificate_info(self):
        url = self.url_entry.get()
        self.output_text.insert(tk.END, f"Fetching SSL certificate info for {url}...\n")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=url) as ssock:
                    cert = ssock.getpeercert()
                    self.output_text.insert(tk.END, f"SSL Certificate Info:\n{cert}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error fetching SSL certificate: {e}\n")

    def track_route(self):
        """Track the route to the specified website using traceroute."""
        url = self.url_entry.get()
        self.output_text.insert(tk.END, f"Tracking route to {url}...\n")

        try:
            # Resolve the IP address of the website
            ip = socket.gethostbyname(url)
            self.output_text.insert(tk.END, f"Resolved IP: {ip}\n")

            # Perform traceroute
            result, _ = traceroute(ip, maxttl=30, verbose=0)  # Set maxttl to limit the number of hops
            self.output_text.insert(tk.END, "Traceroute Results:\n")

            for sent, received in result:
                if received:
                    self.output_text.insert(tk.END, f"Hop {sent.ttl}: {received.src}\n")
                else:
                    self.output_text.insert(tk.END, f"Hop {sent.ttl}: *\n")

        except Exception as e:
            self.output_text.insert(tk.END, f"Error during traceroute: {e}\n")


class SSHConnectionWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("SSH Connection")
        self.geometry("500x300")
        self.configure(bg="#1e1e2f")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TLabel", foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", background="#3e3e56", foreground="#ffffff")

        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="SSH Connection", font=("Helvetica", 16, "bold")).pack(pady=10)

        ttk.Label(self, text="Host:").pack(pady=5)
        self.host_entry = ttk.Entry(self, width=30)
        self.host_entry.pack(pady=5)

        ttk.Label(self, text="Port:").pack(pady=5)
        self.port_entry = ttk.Entry(self, width=30)
        self.port_entry.insert(0, "22")  # Default SSH port
        self.port_entry.pack(pady=5)

        ttk.Label(self, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self, width=30)
        self.username_entry.pack(pady=5)

        ttk.Label(self, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self, width=30, show="*")
        self.password_entry.pack(pady=5)

        ttk.Button(self, text="Connect", command=self.connect_ssh).pack(pady=10)

        self.output_text = tk.Text(self, wrap="word", height=10, bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.output_text.pack(pady=5, fill="both", expand=True)

    def connect_ssh(self):
        """Connect to the remote server using SSH."""
        host = self.host_entry.get()
        port = int(self.port_entry.get())
        username = self.username_entry.get()
        password = self.password_entry.get()

        self.output_text.insert(tk.END, f"Connecting to {host}:{port}...\n")

        try:
            # Create an SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, port=port, username=username, password=password)

            self.output_text.insert(tk.END, "SSH connection established.\n")

            # Execute a command on the remote server
            stdin, stdout, stderr = ssh.exec_command("ls -l")
            output = stdout.read().decode()
            self.output_text.insert(tk.END, f"Command Output:\n{output}\n")

            # Close the SSH connection
            ssh.close()
            self.output_text.insert(tk.END, "SSH connection closed.\n")

        except Exception as e:
            self.output_text.insert(tk.END, f"Error connecting via SSH: {e}\n")

if __name__ == "__main__":
    app = NetworkScanner()
    app.mainloop()
