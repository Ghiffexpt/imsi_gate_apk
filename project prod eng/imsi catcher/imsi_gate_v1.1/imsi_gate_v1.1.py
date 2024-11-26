import socket
import threading
from tkinter import Tk, Text, Label, Entry, Button, Scrollbar, END, VERTICAL, ttk

class UDPServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("UDP Server with Parsing and Threshold")
        self.clients = set()

        # Konfigurasi grid layout untuk responsif
        for i in range(8):
            root.columnconfigure(i, weight=1)
        root.rowconfigure(4, weight=1)
        
        # Label dan input untuk IP dan port
        Label(root, text="IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ip_entry = Entry(root, width=15)
        self.ip_entry.insert(0, "0.0.0.0")
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        Label(root, text="Port:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.port_entry = Entry(root, width=5)
        self.port_entry.insert(0, "5005")
        self.port_entry.grid(row=0, column=3, padx=5, pady=5, sticky="ew")
        
        # Tombol untuk memulai dan menghentikan server
        self.start_button = Button(root, text="Start Server", command=self.start_server)
        self.start_button.grid(row=0, column=4, padx=5, pady=5, sticky="ew")
        self.stop_button = Button(root, text="Stop Server", command=self.stop_server, state='disabled')
        self.stop_button.grid(row=1, column=4, padx=5, pady=5, sticky="ew")
        

        # Tombol untuk mengirim StartCell dan StopCell
        self.start_cell_button = Button(root, text="StartCell", command=self.send_start_cell, state='disabled')
        self.start_cell_button.grid(row=0, column=5, padx=5, pady=5, sticky="ew")
        self.stop_cell_button = Button(root, text="StopCell", command=self.send_stop_cell, state='disabled')
        self.stop_cell_button.grid(row=1, column=5, padx=5, pady=5, sticky="ew")
        
        # Input Threshold
        Label(root, text="RSRP Threshold:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.threshold_entry = Entry(root, width=10)
        self.threshold_entry.insert(0, "0")
        self.threshold_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        # Area log untuk mencatat aktivitas
        self.log_area = Text(root, height=10, wrap='word', state='disabled')
        self.log_area.grid(row=2, column=0, columnspan=8, padx=5, pady=5, sticky="nsew")
        self.scrollbar = Scrollbar(root, command=self.log_area.yview, orient=VERTICAL)
        self.scrollbar.grid(row=2, column=8, sticky='ns', pady=5)
        self.log_area['yscrollcommand'] = self.scrollbar.set
        
        # Tabel untuk data IP, IMSI, dan RSRP
        # Tabel untuk data IP, IMSI, RSRP, dan ulRssi
        self.clear_table_button = Button(root, text="Clear Table", command=self.clear_table)
        self.clear_table_button.grid(row=3, column=7, padx=5, pady=5, sticky="ew")
        Label(root, text="Connected Clients:").grid(row=3, column=0, columnspan=8, padx=5, pady=5, sticky="w")
        self.table = ttk.Treeview(root, columns=("IP", "IMSI", "RSRP", "ulRssi"), show='headings', height=10)
        self.table.heading("IP", text="IP")
        self.table.heading("IMSI", text="IMSI")
        self.table.heading("RSRP", text="RSRP")
        self.table.heading("ulRssi", text="ulRssi")  # Tambahkan heading untuk ulRssi
        self.table.column("IP", width=150)
        self.table.column("IMSI", width=200)
        self.table.column("RSRP", width=100)
        self.table.column("ulRssi", width=100)  # Set ukuran kolom ulRssi
        self.table.grid(row=4, column=0, columnspan=8, padx=5, pady=5, sticky="nsew")
        self.table_scroll = Scrollbar(root, command=self.table.yview, orient=VERTICAL)
        self.table_scroll.grid(row=4, column=8, sticky='ns', pady=5)
        self.table['yscrollcommand'] = self.table_scroll.set

        # Status server
        self.server_running = False
        self.server_socket = None
        # Tambahkan tombol Clear Table

        # Metode untuk membersihkan tabel
    def clear_table(self):
        for item in self.table.get_children():
            self.table.delete(item)
        self.log_message("Table cleared.")

    def start_server(self):
        if self.server_running:
            self.log_message("Server is already running.")
            return
        
        try:
            ip = self.ip_entry.get()
            port = int(self.port_entry.get())
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.bind((ip, port))
            self.server_running = True
            self.log_message(f"Server started at {ip}:{port}")
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.start_cell_button.config(state='normal')
            self.stop_cell_button.config(state='normal')
            threading.Thread(target=self.listen_for_clients, daemon=True).start()
        except Exception as e:
            self.log_message(f"Error starting server: {e}")

    def listen_for_clients(self):
        while self.server_running:
            try:
                data, addr = self.server_socket.recvfrom(1024)
                message = data.decode('utf-8')
                
                # Periksa apakah client sudah ada
                if addr not in self.clients:
                    self.clients.add(addr)  # Tambahkan client baru
                    self.log_message(f"New client connected: {addr}")
                
                self.log_message(f"Received from {addr}: {message}")
                self.add_client_data(addr, message)
            except Exception as e:
                if self.server_running:
                    self.log_message(f"Error: {e}")


    def add_client_data(self, addr, message):
        try:
            ip = addr[0]
            imsi = self.extract_value(message, "imsi")
            rsrp = self.extract_value(message, "rsrp", default="0")
            ulrssi = self.extract_value(message, "ulRssi", default="0")  # Ambil ulRssi dari pesan
        
            # Validasi IMSI dan RSRP
            if imsi == "Unknown" or imsi == "000000000000000":
                self.log_message(f"Data from {ip} ignored: IMSI is missing or invalid.")
                return
        
            try:
                rsrp_value = float(rsrp)
                ulrssi_value = float(ulrssi)  # Validasi ulRssi sebagai angka
            except ValueError:
                self.log_message(f"Data from {ip} ignored: RSRP or ulRssi is not a valid number.")
                return
        
            # Ambil threshold dari input
            threshold = float(self.threshold_entry.get())
            if rsrp_value < threshold:
                self.log_message(f"Data from {ip} ignored: RSRP {rsrp_value} below threshold ({threshold}).")
                return
        
            # Tambahkan data ke tabel
            self.table.insert("", END, values=(ip, imsi, rsrp, ulrssi))  # Tambahkan ulRssi
            self.log_message(f"Data added: IP={ip}, IMSI={imsi}, RSRP={rsrp}, ulRssi={ulrssi}.")
        except Exception as e:
            self.log_message(f"Error adding client data: {e}")



    def extract_value(self, message, key, default="Unknown"):
        try:
            for part in message.split():
                if key in part:
                    return part.split("[")[1].split("]")[0]
            return default
        except Exception:
            return default

    def send_start_cell(self):
        self.broadcast_message("StartCell")

    def send_stop_cell(self):
        self.broadcast_message("StopCell")

    def broadcast_message(self, message):
        try:
            if not self.clients:
                self.log_message("No clients connected.")
                return
            
            for client in list(self.clients):  # Gunakan list() agar set bisa dimodifikasi
                try:
                    self.server_socket.sendto(message.encode('utf-8'), client)
                    self.log_message(f"Sent to {client}: {message}")
                except Exception as e:
                    self.log_message(f"Error sending to {client}: {e}")
                    self.clients.remove(client)  # Hapus client yang gagal
        except Exception as e:
            self.log_message(f"Error broadcasting message: {e}")

    def stop_server(self):
        if self.server_running:
            self.server_running = False
            if self.server_socket:
                self.server_socket.close()
            self.log_message("Server stopped.")
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            self.start_cell_button.config(state='disabled')
            self.stop_cell_button.config(state='disabled')

    def log_message(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(END, f"{message}\n")
        self.log_area.see(END)
        self.log_area.config(state='disabled')

if __name__ == "__main__":
    root = Tk()
    app = UDPServerGUI(root)
    root.mainloop()
