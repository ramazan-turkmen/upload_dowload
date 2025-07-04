#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Proje Adı: SSH File Transfer
Yazar: [Ramazan Türkmen]
E-posta: [email@]
GitHub: [https://github.com/ramazan-turkmen]
Oluşturulma Tarihi: 04/07/2025
Açıklama: "Bu proje, paramiko kütüphanesiyle SSH üzerinden dosya yükleme (upload) ve indirme (download) işlemlerini otomatize eder. Kullanıcı dostu arayüzüyle lokal ve uzak sunucular arasında güvenli veri transferi sağlar."
"""

import json
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import paramiko
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from stat import S_ISDIR
import time

class ModernSSHTransferApp:
    def __init__(self, master):
        self.master = master
        master.title("SSH File Transfer")
        master.geometry("1000x750")
        
        # Style Configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        # Configuration
        self.CONFIG_FILE = "ssh_transfer_config.json"
        self.cancel_flag = False
        self.ssh_client = None
        self.sftp_client = None
        self.current_remote_path = "/"
        
        # Main Paned Window
        self.main_paned = ttk.PanedWindow(master, orient=tk.HORIZONTAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True)
        
        # Left Frame (Connection and File Selection)
        self.left_frame = ttk.Frame(self.main_paned, width=300)
        self.main_paned.add(self.left_frame)
        
        # Right Frame (File Browser and Logs)
        self.right_frame = ttk.Frame(self.main_paned)
        self.main_paned.add(self.right_frame)
        
        # Setup all components
        self.setup_connection_frame()
        self.setup_transfer_frame()
        self.setup_file_browser()
        self.setup_status_area()
        
        # Load configuration
        self.load_config()

    def configure_styles(self):
        """Configure modern styles for widgets"""
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Segoe UI', 9))
        self.style.configure('TButton', font=('Segoe UI', 9))
        self.style.configure('TEntry', font=('Segoe UI', 9))
        self.style.configure('TNotebook', background='#f0f0f0')
        self.style.configure('TNotebook.Tab', font=('Segoe UI', 9))
        self.style.configure('Treeview', font=('Segoe UI', 9), rowheight=25)
        self.style.configure('Treeview.Heading', font=('Segoe UI', 9, 'bold'))
        self.style.map('TButton', 
                      foreground=[('disabled', 'gray'), ('active', 'white')],
                      background=[('disabled', '#e0e0e0'), ('active', '#0052cc')])
        
        # Custom styles
        self.style.configure('success.TLabel', foreground='green')
        self.style.configure('error.TLabel', foreground='red')
        self.style.configure('info.TLabel', foreground='blue')

    def setup_connection_frame(self):
        """Setup the connection panel"""
        conn_frame = ttk.LabelFrame(self.left_frame, text="SSH Connection", padding=10)
        conn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # IP Address
        ttk.Label(conn_frame, text="Host IP:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.ip_entry = ttk.Entry(conn_frame, width=25)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=2)
        
        # Username
        ttk.Label(conn_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.user_entry = ttk.Entry(conn_frame, width=25)
        self.user_entry.grid(row=1, column=1, padx=5, pady=2)
        
        # Password
        ttk.Label(conn_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.pass_entry = ttk.Entry(conn_frame, show="*", width=25)
        self.pass_entry.grid(row=2, column=1, padx=5, pady=2)
        self.show_pass = False
        self.toggle_btn = ttk.Button(conn_frame, text="Show", width=6, command=self.toggle_password)
        self.toggle_btn.grid(row=2, column=2, padx=5)
        
        # Connection Buttons
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        self.test_btn = ttk.Button(btn_frame, text="Test", command=self.test_connection_thread)
        self.test_btn.pack(side=tk.LEFT, padx=2)
        
        self.connect_btn = ttk.Button(btn_frame, text="Connect", command=self.connect_thread)
        self.connect_btn.pack(side=tk.LEFT, padx=2)
        
        self.disconnect_btn = ttk.Button(btn_frame, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=2)
        
        # Config Buttons
        config_frame = ttk.Frame(conn_frame)
        config_frame.grid(row=4, column=0, columnspan=3, pady=5)
        
        self.save_btn = ttk.Button(config_frame, text="Save Config", command=self.save_config)
        self.save_btn.pack(side=tk.LEFT, padx=2)
        
        self.load_btn = ttk.Button(config_frame, text="Load Config", command=self.load_config)
        self.load_btn.pack(side=tk.LEFT, padx=2)

    def setup_transfer_frame(self):
        """Setup the file transfer panel"""
        transfer_frame = ttk.LabelFrame(self.left_frame, text="File Transfer", padding=10)
        transfer_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Operation Notebook
        self.transfer_notebook = ttk.Notebook(transfer_frame)
        self.transfer_notebook.pack(fill=tk.X)
        
        # Upload Tab
        self.upload_tab = ttk.Frame(self.transfer_notebook)
        self.transfer_notebook.add(self.upload_tab, text="Upload")
        self.setup_upload_tab()
        
        # Download Tab
        self.download_tab = ttk.Frame(self.transfer_notebook)
        self.transfer_notebook.add(self.download_tab, text="Download")
        self.setup_download_tab()

    def setup_upload_tab(self):
        """Setup the upload tab components"""
        # Local Files
        ttk.Label(self.upload_tab, text="Local Files:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.local_files_var = tk.StringVar()
        self.local_files_entry = ttk.Entry(self.upload_tab, textvariable=self.local_files_var, state='readonly')
        self.local_files_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        self.browse_btn = ttk.Button(self.upload_tab, text="Browse", command=self.browse_local_files)
        self.browse_btn.grid(row=0, column=2, padx=5)
        
        # Remote Directory
        ttk.Label(self.upload_tab, text="Remote Directory:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.remote_upload_dir = ttk.Entry(self.upload_tab)
        self.remote_upload_dir.grid(row=1, column=1, columnspan=2, padx=5, pady=2, sticky=tk.EW)
        self.remote_upload_dir.insert(0, "/home/")
        
        # IP List
        ttk.Label(self.upload_tab, text="Target IPs (one per line):").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.ip_list_text = scrolledtext.ScrolledText(self.upload_tab, width=25, height=5)
        self.ip_list_text.grid(row=3, column=0, columnspan=3, padx=5, pady=2, sticky=tk.EW)
        
        # IP List Buttons
        ip_list_btn_frame = ttk.Frame(self.upload_tab)
        ip_list_btn_frame.grid(row=4, column=0, columnspan=3, pady=5)
        
        self.save_ip_list_btn = ttk.Button(ip_list_btn_frame, text="Save IPs", command=self.save_ip_list)
        self.save_ip_list_btn.pack(side=tk.LEFT, padx=2)
        
        self.load_ip_list_btn = ttk.Button(ip_list_btn_frame, text="Load IPs", command=self.load_ip_list)
        self.load_ip_list_btn.pack(side=tk.LEFT, padx=2)
        
        # Upload Buttons
        upload_btn_frame = ttk.Frame(self.upload_tab)
        upload_btn_frame.grid(row=5, column=0, columnspan=3, pady=5)
        
        self.upload_single_btn = ttk.Button(upload_btn_frame, text="Upload to Current", command=self.upload_files_thread)
        self.upload_single_btn.pack(side=tk.LEFT, padx=2)
        
        self.upload_all_btn = ttk.Button(upload_btn_frame, text="Upload to All", command=self.upload_to_all_thread)
        self.upload_all_btn.pack(side=tk.LEFT, padx=2)
        
        self.cancel_upload_btn = ttk.Button(upload_btn_frame, text="Cancel", command=self.cancel_upload, state=tk.DISABLED)
        self.cancel_upload_btn.pack(side=tk.LEFT, padx=2)
        
        # Configure grid weights
        self.upload_tab.columnconfigure(1, weight=1)

    def setup_download_tab(self):
        """Setup the download tab components"""
        # Remote Path
        ttk.Label(self.download_tab, text="Remote Path:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.remote_path_entry = ttk.Entry(self.download_tab)
        self.remote_path_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        self.remote_path_entry.insert(0, "/")
        
        # Local Directory
        ttk.Label(self.download_tab, text="Local Directory:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.local_dir_entry = ttk.Entry(self.download_tab)
        self.local_dir_entry.grid(row=1, column=1, padx=5, pady=2, sticky=tk.EW)
        self.browse_local_btn = ttk.Button(self.download_tab, text="Browse", command=self.browse_local_directory)
        self.browse_local_btn.grid(row=1, column=2, padx=5)
        
        # Download Buttons
        download_btn_frame = ttk.Frame(self.download_tab)
        download_btn_frame.grid(row=2, column=0, columnspan=3, pady=5)
        
        self.download_btn = ttk.Button(download_btn_frame, text="Download Selected", command=self.download_selected_thread)
        self.download_btn.pack(side=tk.LEFT, padx=2)
        
        self.download_folder_btn = ttk.Button(download_btn_frame, text="Download Folder", command=self.download_folder_thread)
        self.download_folder_btn.pack(side=tk.LEFT, padx=2)
        
        self.cancel_download_btn = ttk.Button(download_btn_frame, text="Cancel", command=self.cancel_download, state=tk.DISABLED)
        self.cancel_download_btn.pack(side=tk.LEFT, padx=2)
        
        # Configure grid weights
        self.download_tab.columnconfigure(1, weight=1)

    def setup_file_browser(self):
        """Setup the remote file browser"""
        browser_frame = ttk.LabelFrame(self.right_frame, text="Remote File Browser", padding=10)
        browser_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Navigation buttons
        nav_frame = ttk.Frame(browser_frame)
        nav_frame.pack(fill=tk.X, pady=5)
        
        self.refresh_btn = ttk.Button(nav_frame, text="Refresh", command=self.list_remote_files)
        self.refresh_btn.pack(side=tk.LEFT, padx=2)
        
        self.up_dir_btn = ttk.Button(nav_frame, text="Up", command=self.go_up_directory)
        self.up_dir_btn.pack(side=tk.LEFT, padx=2)
        
        # Treeview for files
        self.remote_files_tree = ttk.Treeview(browser_frame, columns=("Size", "Type", "Modified"), selectmode="extended")
        self.remote_files_tree.heading("#0", text="Name")
        self.remote_files_tree.heading("Size", text="Size")
        self.remote_files_tree.heading("Type", text="Type")
        self.remote_files_tree.heading("Modified", text="Modified")
        
        self.remote_files_tree.column("#0", width=250)
        self.remote_files_tree.column("Size", width=100, anchor=tk.E)
        self.remote_files_tree.column("Type", width=100)
        self.remote_files_tree.column("Modified", width=150)
        
        self.remote_files_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind double click to navigate directories
        self.remote_files_tree.bind("<Double-1>", self.on_remote_item_double_click)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.remote_files_tree, orient="vertical", command=self.remote_files_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.remote_files_tree.configure(yscrollcommand=scrollbar.set)

    def setup_status_area(self):
        """Setup the status and log area"""
        status_frame = ttk.Frame(self.right_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Status Label
        self.status_label = ttk.Label(status_frame, text="Ready", style='info.TLabel')
        self.status_label.pack(side=tk.TOP, fill=tk.X, pady=2)
        
        # Progress Bar
        self.progress = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Log Area
        log_frame = ttk.LabelFrame(self.right_frame, text="Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, width=100, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    # ======================
    # Connection Methods
    # ======================
    def toggle_password(self):
        """Toggle password visibility"""
        if self.show_pass:
            self.pass_entry.config(show="*")
            self.toggle_btn.config(text="Show")
            self.show_pass = False
        else:
            self.pass_entry.config(show="")
            self.toggle_btn.config(text="Hide")
            self.show_pass = True

    def test_connection_thread(self):
        """Start connection test in a thread"""
        thread = threading.Thread(target=self.test_connection)
        thread.start()

    def test_connection(self):
        """Test SSH connection"""
        ip = self.ip_entry.get().strip()
        user = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()

        if not ip or not user or not password:
            messagebox.showwarning("Missing Info", "Please enter IP, username and password")
            return

        self.update_status("Testing connection...")
        self.log("Connection test started")

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=user, password=password, timeout=10)
            self.update_status("Connection successful!", success=True)
            self.log("Connection successful")
            client.close()
            return True
        except Exception as e:
            self.update_status(f"Connection failed: {str(e)}", error=True)
            self.log(f"Connection error: {e}")
            return False

    def connect_thread(self):
        """Start connection in a thread"""
        thread = threading.Thread(target=self.connect)
        thread.start()

    def connect(self):
        """Connect to SSH server"""
        ip = self.ip_entry.get().strip()
        user = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()

        if not ip or not user or not password:
            messagebox.showwarning("Missing Info", "Please enter IP, username and password")
            return

        self.update_status(f"Connecting to {ip}...")
        self.log(f"Connecting to {ip}")

        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(ip, username=user, password=password, timeout=10)
            self.sftp_client = self.ssh_client.open_sftp()
            
            self.update_status(f"Connected to {ip}", success=True)
            self.log(f"Connected to {ip}")
            
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.test_btn.config(state=tk.DISABLED)
            
            # List files in root directory
            self.list_remote_files()
            
        except Exception as e:
            self.update_status(f"Connection failed: {str(e)}", error=True)
            self.log(f"Connection error: {e}")
            if self.sftp_client:
                self.sftp_client.close()
            if self.ssh_client:
                self.ssh_client.close()

    def disconnect(self):
        """Disconnect from SSH server"""
        try:
            if self.sftp_client:
                self.sftp_client.close()
            if self.ssh_client:
                self.ssh_client.close()
                
            self.update_status("Disconnected")
            self.log("Disconnected successfully")
            
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.test_btn.config(state=tk.NORMAL)
            
            # Clear file list
            self.remote_files_tree.delete(*self.remote_files_tree.get_children())
            
        except Exception as e:
            self.log(f"Error while disconnecting: {e}")

    # ======================
    # File Browser Methods
    # ======================
    def list_remote_files(self):
        """List files in remote directory"""
        if not self.sftp_client:
            messagebox.showwarning("Error", "Not connected to server!")
            return

        path = self.remote_path_entry.get().strip() if hasattr(self, 'remote_path_entry') else self.current_remote_path
        if not path:
            path = "/"
            
        try:
            self.remote_files_tree.delete(*self.remote_files_tree.get_children())
            self.update_status(f"Listing {path}...")
            self.log(f"Getting directory listing for {path}")
            
            for item in self.sftp_client.listdir_attr(path):
                full_path = f"{path.rstrip('/')}/{item.filename}"
                modified_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item.st_mtime))
                
                if S_ISDIR(item.st_mode):
                    # Directory
                    self.remote_files_tree.insert("", "end", text=item.filename + "/", 
                                                values=("-", "Directory", modified_time), tags=("dir",))
                else:
                    # File
                    size = self.format_size(item.st_size)
                    file_type = self.get_file_type(item.filename)
                    self.remote_files_tree.insert("", "end", text=item.filename, 
                                                values=(size, file_type, modified_time), tags=("file",))
            
            self.remote_files_tree.tag_configure("dir", foreground="blue")
            self.remote_files_tree.tag_configure("file", foreground="black")
            
            self.current_remote_path = path
            self.update_status(f"Directory listing complete: {path}", success=True)
            self.log(f"Directory listing complete for {path}")
            
        except Exception as e:
            self.update_status(f"Error listing {path}: {str(e)}", error=True)
            self.log(f"Directory listing error: {e}")

    def on_remote_item_double_click(self, event):
        """Handle double click on remote file item"""
        selected_item = self.remote_files_tree.selection()
        if not selected_item:
            return
            
        item = self.remote_files_tree.item(selected_item[0])
        if "dir" in item["tags"]:
            new_path = f"{self.current_remote_path.rstrip('/')}/{item['text'].rstrip('/')}"
            self.remote_path_entry.delete(0, tk.END)
            self.remote_path_entry.insert(0, new_path)
            self.list_remote_files()

    def go_up_directory(self):
        """Navigate to parent directory"""
        if not self.sftp_client:
            messagebox.showwarning("Error", "Not connected to server!")
            return

        current_path = self.remote_path_entry.get().strip() if hasattr(self, 'remote_path_entry') else self.current_remote_path
        if current_path == "/":
            return
            
        parent_path = os.path.dirname(current_path.rstrip('/'))
        if not parent_path:
            parent_path = "/"
            
        self.remote_path_entry.delete(0, tk.END)
        self.remote_path_entry.insert(0, parent_path)
        self.list_remote_files()

    # ======================
    # File Transfer Methods
    # ======================
    def browse_local_files(self):
        """Browse for local files to upload"""
        files = filedialog.askopenfilenames(title="Select files to upload")
        if files:
            self.local_files_var.set(", ".join(files))

    def browse_local_directory(self):
        """Browse for local directory to save downloads"""
        directory = filedialog.askdirectory(title="Select download directory")
        if directory:
            self.local_dir_entry.delete(0, tk.END)
            self.local_dir_entry.insert(0, directory)

    def upload_files_thread(self):
        """Start file upload in a thread"""
        thread = threading.Thread(target=self.upload_files)
        thread.start()

    def upload_files(self):
        """Upload files to current server"""
        if not self.sftp_client:
            messagebox.showwarning("Error", "Not connected to server!")
            return

        files = self.local_files_var.get().split(", ")
        if not files or files == [""]:
            messagebox.showwarning("Error", "Please select files to upload!")
            return

        remote_dir = self.remote_upload_dir.get().strip()
        if not remote_dir:
            messagebox.showwarning("Error", "Please specify remote directory!")
            return

        self.cancel_flag = False
        self.cancel_upload_btn.config(state=tk.NORMAL)
        self.upload_single_btn.config(state=tk.DISABLED)
        self.upload_all_btn.config(state=tk.DISABLED)
        
        ip = self.ip_entry.get().strip()
        self.update_status(f"Uploading to {ip}...")
        self.log(f"\n>>> Starting upload to {ip}")

        try:
            total_files = len(files)
            self.progress["value"] = 0
            self.progress["maximum"] = total_files
            
            for index, file in enumerate(files, 1):
                if self.cancel_flag:
                    break
                    
                filename = os.path.basename(file)
                remote_path = remote_dir.rstrip("/") + "/" + filename
                self.update_status(f"Uploading {filename} ({index}/{total_files})")
                self.log(f"Uploading '{file}' -> {remote_path}")
                
                self.sftp_client.put(file, remote_path)
                self.progress["value"] = index
                self.master.update_idletasks()
            
            if not self.cancel_flag:
                self.update_status(f"Upload to {ip} completed!", success=True)
                self.log(f"<<< Upload to {ip} completed successfully")
            else:
                self.update_status(f"Upload to {ip} canceled!")
                self.log(f"<<< Upload to {ip} canceled")

        except Exception as e:
            self.update_status(f"Upload error: {str(e)}", error=True)
            self.log(f"<<< Upload error: {str(e)}")
            if "Authentication failed" in str(e):
                self.log("Error: Authentication failed. Check username/password.")
            elif "No route to host" in str(e):
                self.log("Error: Cannot reach host. Check IP or network connection.")

        finally:
            self.cancel_upload_btn.config(state=tk.DISABLED)
            self.upload_single_btn.config(state=tk.NORMAL)
            self.upload_all_btn.config(state=tk.NORMAL)

    def upload_to_all_thread(self):
        """Start multi-server upload in a thread"""
        thread = threading.Thread(target=self.upload_to_all)
        thread.start()

    def upload_to_all(self):
        """Upload files to all IPs in the list"""
        files = self.local_files_var.get().split(", ")
        if not files or files == [""]:
            messagebox.showwarning("Error", "Please select files to upload!")
            return

        remote_dir = self.remote_upload_dir.get().strip()
        if not remote_dir:
            messagebox.showwarning("Error", "Please specify remote directory!")
            return

        ip_list = self.ip_list_text.get("1.0", tk.END).strip().split('\n')
        ip_list = [ip.strip() for ip in ip_list if ip.strip()]
        
        if not ip_list:
            messagebox.showwarning("Error", "IP list is empty!")
            return

        self.cancel_flag = False
        self.cancel_upload_btn.config(state=tk.NORMAL)
        self.upload_single_btn.config(state=tk.DISABLED)
        self.upload_all_btn.config(state=tk.DISABLED)
        
        user = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()
        total_ips = len(ip_list)
        success_count = 0
        failed_ips = []

        self.update_status(f"Starting batch upload to {total_ips} servers...")
        self.log(f"\n=== Starting batch upload to {total_ips} servers ===")
        
        self.progress["value"] = 0
        self.progress["maximum"] = total_ips

        # Parallel upload with thread pool (max 5 concurrent connections)
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.upload_to_ip, ip, user, password, remote_dir, files): ip for ip in ip_list}
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        success_count += 1
                    else:
                        failed_ips.append(ip)
                except Exception as e:
                    failed_ips.append(ip)
                    self.log(f"Unexpected error with {ip}: {str(e)}")
                
                self.progress["value"] = len(failed_ips) + success_count
                self.master.update_idletasks()

        # Report results
        if not self.cancel_flag:
            self.update_status(f"Batch upload complete! Success: {success_count}/{total_ips}", success=True)
            self.log(f"\n=== BATCH UPLOAD RESULTS: {success_count} successful, {total_ips-success_count} failed ===")
            
            if failed_ips:
                self.log("\nFailed IPs:")
                for ip in failed_ips:
                    self.log(f"- {ip}")
        else:
            self.update_status(f"Batch upload canceled. Completed: {success_count}/{total_ips}")

        self.cancel_upload_btn.config(state=tk.DISABLED)
        self.upload_single_btn.config(state=tk.NORMAL)
        self.upload_all_btn.config(state=tk.NORMAL)

    def upload_to_ip(self, ip, user, password, remote_dir, files):
        """Upload files to a single IP (for thread pool)"""
        if self.cancel_flag:
            return False

        try:
            transport = paramiko.Transport((ip, 22))
            transport.connect(username=user, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)

            for file in files:
                if self.cancel_flag:
                    break
                filename = os.path.basename(file)
                remote_path = remote_dir.rstrip("/") + "/" + filename
                sftp.put(file, remote_path)

            sftp.close()
            transport.close()
            
            if not self.cancel_flag:
                self.log(f"Upload to {ip} successful")
                return True
            return False

        except Exception as e:
            self.log(f"Upload to {ip} failed: {str(e)}")
            return False

    def download_selected_thread(self):
        """Start download of selected files in a thread"""
        thread = threading.Thread(target=self.download_selected)
        thread.start()

    def download_selected(self):
        """Download selected files from server"""
        if not self.sftp_client:
            messagebox.showwarning("Error", "Not connected to server!")
            return

        local_dir = self.local_dir_entry.get().strip()
        if not local_dir:
            messagebox.showwarning("Error", "Please select local directory!")
            return

        selected_items = self.remote_files_tree.selection()
        if not selected_items:
            messagebox.showwarning("Error", "Please select files/folders to download!")
            return

        self.cancel_flag = False
        self.cancel_download_btn.config(state=tk.NORMAL)
        self.download_btn.config(state=tk.DISABLED)
        self.download_folder_btn.config(state=tk.DISABLED)
        
        remote_path = self.current_remote_path
        total_files = len(selected_items)
        success_count = 0
        
        self.progress["value"] = 0
        self.progress["maximum"] = total_files
        
        for index, item_id in enumerate(selected_items, 1):
            if self.cancel_flag:
                break
                
            item = self.remote_files_tree.item(item_id)
            item_name = item["text"]
            is_dir = "dir" in item["tags"]
            remote_item_path = f"{remote_path.rstrip('/')}/{item_name.rstrip('/')}"
            
            try:
                if is_dir:
                    self.update_status(f"Downloading folder: {item_name} ({index}/{total_files})")
                    self.log(f"\nDownloading folder: {remote_item_path}")
                    file_count = self.download_directory(remote_item_path, os.path.join(local_dir, item_name))
                    success_count += 1
                    self.log(f"Folder downloaded successfully ({file_count} files)")
                else:
                    self.update_status(f"Downloading file: {item_name} ({index}/{total_files})")
                    self.log(f"\nDownloading file: {remote_item_path}")
                    self.sftp_client.get(remote_item_path, os.path.join(local_dir, item_name))
                    success_count += 1
                    self.log(f"File downloaded successfully")
                
            except Exception as e:
                self.log(f"Download error ({item_name}): {e}")
                
            finally:
                self.progress["value"] = index
                self.master.update_idletasks()
        
        if not self.cancel_flag:
            self.update_status(f"Download complete! Success: {success_count}/{total_files}", success=True)
        else:
            self.update_status(f"Download canceled. Completed: {success_count}/{index-1}")
            
        self.cancel_download_btn.config(state=tk.DISABLED)
        self.download_btn.config(state=tk.NORMAL)
        self.download_folder_btn.config(state=tk.NORMAL)

    def download_folder_thread(self):
        """Start folder download in a thread"""
        thread = threading.Thread(target=self.download_folder)
        thread.start()

    def download_folder(self):
        """Download selected folder from server"""
        if not self.sftp_client:
            messagebox.showwarning("Error", "Not connected to server!")
            return

        selected_items = self.remote_files_tree.selection()
        if not selected_items or len(selected_items) > 1:
            messagebox.showwarning("Error", "Please select exactly one folder!")
            return

        item = self.remote_files_tree.item(selected_items[0])
        if "dir" not in item["tags"]:
            messagebox.showwarning("Error", "Please select a folder!")
            return

        local_dir = self.local_dir_entry.get().strip()
        if not local_dir:
            messagebox.showwarning("Error", "Please select local directory!")
            return

        self.cancel_flag = False
        self.cancel_download_btn.config(state=tk.NORMAL)
        self.download_btn.config(state=tk.DISABLED)
        self.download_folder_btn.config(state=tk.DISABLED)
        
        remote_path = self.current_remote_path
        folder_name = item["text"].rstrip('/')
        remote_folder_path = f"{remote_path.rstrip('/')}/{folder_name}"
        local_folder_path = os.path.join(local_dir, folder_name)
        
        self.update_status(f"Downloading folder: {folder_name}")
        self.log(f"\nDownloading folder: {remote_folder_path}")
        
        try:
            # Download folder structure and files
            file_count = self.download_directory(remote_folder_path, local_folder_path)
            
            if not self.cancel_flag:
                self.update_status(f"Folder downloaded successfully! ({file_count} files)", success=True)
                self.log(f"Folder download complete. Total {file_count} files downloaded.")
            else:
                self.update_status(f"Folder download canceled.")
                
        except Exception as e:
            self.update_status(f"Folder download error!", error=True)
            self.log(f"Folder download error: {e}")
            
        finally:
            self.cancel_download_btn.config(state=tk.DISABLED)
            self.download_btn.config(state=tk.NORMAL)
            self.download_folder_btn.config(state=tk.NORMAL)

    def download_directory(self, remote_dir, local_dir):
        """Recursively download a directory"""
        if not os.path.exists(local_dir):
            os.makedirs(local_dir)
            
        file_count = 0
        
        for item in self.sftp_client.listdir_attr(remote_dir):
            if self.cancel_flag:
                return file_count
                
            remote_item_path = f"{remote_dir.rstrip('/')}/{item.filename}"
            local_item_path = os.path.join(local_dir, item.filename)
            
            if S_ISDIR(item.st_mode):
                # Download subdirectory
                file_count += self.download_directory(remote_item_path, local_item_path)
            else:
                # Download file
                try:
                    self.sftp_client.get(remote_item_path, local_item_path)
                    file_count += 1
                    self.log(f"Downloaded: {remote_item_path}")
                except Exception as e:
                    self.log(f"Error ({remote_item_path}): {e}")
        
        return file_count

    # ======================
    # Utility Methods
    # ======================
    def save_config(self):
        """Save configuration to file"""
        data = {
            "ip": self.ip_entry.get().strip(),
            "user": self.user_entry.get().strip(),
            "remote_path": self.current_remote_path,
            "remote_upload_dir": self.remote_upload_dir.get().strip(),
            "local_dir": self.local_dir_entry.get().strip()
        }
        try:
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(data, f)
            messagebox.showinfo("Success", "Settings saved successfully")
            self.log("Settings saved")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving settings: {e}")
            self.log(f"Error saving settings: {e}")

    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, data.get("ip", ""))
                
                self.user_entry.delete(0, tk.END)
                self.user_entry.insert(0, data.get("user", ""))
                
                self.current_remote_path = data.get("remote_path", "/")
                if hasattr(self, 'remote_path_entry'):
                    self.remote_path_entry.delete(0, tk.END)
                    self.remote_path_entry.insert(0, self.current_remote_path)
                
                self.remote_upload_dir.delete(0, tk.END)
                self.remote_upload_dir.insert(0, data.get("remote_upload_dir", "/home/"))
                
                self.local_dir_entry.delete(0, tk.END)
                self.local_dir_entry.insert(0, data.get("local_dir", ""))
                
                self.log("Settings loaded")
            except Exception as e:
                messagebox.showerror("Error", f"Error loading settings: {e}")
                self.log(f"Error loading settings: {e}")

    def save_ip_list(self):
        """Save IP list to file"""
        ip_list = self.ip_list_text.get("1.0", tk.END).strip()
        try:
            with open("ip_list.txt", "w") as f:
                f.write(ip_list)
            messagebox.showinfo("Success", "IP list saved successfully")
            self.log("IP list saved")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving IP list: {e}")
            self.log(f"Error saving IP list: {e}")

    def load_ip_list(self):
        """Load IP list from file"""
        if os.path.exists("ip_list.txt"):
            try:
                with open("ip_list.txt", "r") as f:
                    ip_list = f.read()
                self.ip_list_text.delete("1.0", tk.END)
                self.ip_list_text.insert("1.0", ip_list)
                self.log("IP list loaded")
            except Exception as e:
                messagebox.showerror("Error", f"Error loading IP list: {e}")
                self.log(f"Error loading IP list: {e}")

    def cancel_upload(self):
        """Cancel current upload operation"""
        self.cancel_flag = True
        self.update_status("Canceling upload...")

    def cancel_download(self):
        """Cancel current download operation"""
        self.cancel_flag = True
        self.update_status("Canceling download...")

    def update_status(self, message, success=False, error=False):
        """Update status label with message"""
        self.status_label.config(text=message)
        if success:
            self.status_label.config(style='success.TLabel')
        elif error:
            self.status_label.config(style='error.TLabel')
        else:
            self.status_label.config(style='info.TLabel')

    def log(self, message):
        """Add message to log"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    @staticmethod
    def format_size(size):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    @staticmethod
    def get_file_type(filename):
        """Get file type based on extension"""
        ext = os.path.splitext(filename)[1].lower()
        if ext in ['.txt', '.log', '.csv', '.json', '.xml']:
            return "Text"
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            return "Image"
        elif ext in ['.mp3', '.wav', '.ogg']:
            return "Audio"
        elif ext in ['.mp4', '.avi', '.mov']:
            return "Video"
        elif ext in ['.zip', '.rar', '.tar', '.gz']:
            return "Archive"
        elif ext in ['.py', '.js', '.java', '.c', '.cpp']:
            return "Code"
        elif ext in ['.pdf', '.doc', '.docx', '.xls', '.ppt']:
            return "Document"
        else:
            return "File"

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernSSHTransferApp(root)
    root.mainloop()