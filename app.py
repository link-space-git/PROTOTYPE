import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import subprocess
import json

class BackupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("System Backup Manager")
        self.root.geometry("800x600")
        
        # Configuration
        self.source_dir = r'C:\1CAPSTONE\1_SYSTEM'
        self.backup_dir = r'C:\1CAPSTONE\Backup'
        self.default_backup = r'C:\1CAPSTONE\Backup\17032025_Backup'
        self.restore_target_dir = r'C:\1CAPSTONE\1_SYSTEM'  # Default restore target
        
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_backup_tab()
        self.create_scan_tab()
        self.create_restore_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")
    
    def update_status(self, message):
        self.status_var.set(message)
        self.root.update()
    
    def create_backup_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Backup")
        
        tk.Label(tab, text="Backup Name:").pack(pady=5)
        self.backup_name_entry = tk.Entry(tab, width=40)
        self.backup_name_entry.pack(pady=5)
        
        tk.Button(tab, text="Select Source Directory", 
                 command=self.select_source_dir).pack(pady=5)
        self.source_dir_label = tk.Label(tab, text=f"Source: {self.source_dir}")
        self.source_dir_label.pack(pady=5)
        
        tk.Button(tab, text="Select Backup Directory", 
                 command=self.select_backup_dir).pack(pady=5)
        self.backup_dir_label = tk.Label(tab, text=f"Backup: {self.backup_dir}")
        self.backup_dir_label.pack(pady=5)
        
        tk.Button(tab, text="Create Backup", 
                 command=self.create_backup, bg="lightblue").pack(pady=20)
    
    def create_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Scan")
        
        # System Directory Selection
        tk.Label(tab, text="System Directory:").pack(pady=5)
        tk.Button(tab, text="Select System Directory", 
                command=self.select_system_dir_scan).pack(pady=5)
        self.system_dir_label = tk.Label(tab, text=f"System: {self.source_dir}")
        self.system_dir_label.pack(pady=5)
        
        # Backup Directory Selection
        tk.Label(tab, text="Backup Directory:").pack(pady=5)
        tk.Button(tab, text="Select Backup Directory", 
                command=self.select_backup_dir_scan).pack(pady=5)
        self.scan_backup_label = tk.Label(tab, text=f"Backup: {self.default_backup}")
        self.scan_backup_label.pack(pady=5)
        
        # Scan Button
        tk.Button(tab, text="Run Scan", 
                 command=self.quick_scan, bg="lightgreen").pack(pady=20)
        
        # Results Frame
        results_frame = tk.Frame(tab)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Results Text with Scrollbar
        scrollbar = tk.Scrollbar(results_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.scan_results = tk.Text(results_frame, height=15, wrap=tk.WORD, 
                                  yscrollcommand=scrollbar.set)
        self.scan_results.pack(fill=tk.BOTH, expand=True)
        
        scrollbar.config(command=self.scan_results.yview)
        
        # Configure tags for different message types
        self.scan_results.tag_config("error", foreground="red")
        self.scan_results.tag_config("success", foreground="green")
        self.scan_results.tag_config("warning", foreground="orange")
        self.scan_results.tag_config("info", foreground="blue")
        
        self.scan_results.insert(tk.END, "Scan results will appear here...\n", "info")
    
    def create_restore_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Restore")
        
        # Backup Selection
        tk.Label(tab, text="Select Backup to Restore:").pack(pady=5)
        
        # Backup list frame
        backup_list_frame = tk.Frame(tab)
        backup_list_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.backup_listbox = tk.Listbox(backup_list_frame, height=8)
        self.backup_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(backup_list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.backup_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.backup_listbox.yview)
        
        self.refresh_backup_list()
        
        # Manual backup path selection
        tk.Button(tab, text="Select Custom Backup Directory", 
                 command=self.select_custom_backup).pack(pady=5)
        self.custom_backup_label = tk.Label(tab, text="Custom Backup: Not selected")
        self.custom_backup_label.pack(pady=5)
        
        # Restore target selection
        tk.Button(tab, text="Select Restore Target Directory", 
                 command=self.select_restore_target).pack(pady=5)
        self.restore_target_label = tk.Label(tab, text=f"Restore Target: {self.restore_target_dir}")
        self.restore_target_label.pack(pady=5)
        
        # Action buttons
        button_frame = tk.Frame(tab)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Refresh Backup List", 
                 command=self.refresh_backup_list).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Restore Selected Backup", 
                 command=self.restore_backup, bg="lightcoral").pack(side=tk.LEFT, padx=5)
        
        # Restore results
        self.restore_results = tk.Text(tab, height=8, wrap=tk.WORD)
        self.restore_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.restore_results.tag_config("error", foreground="red")
        self.restore_results.tag_config("success", foreground="green")
        self.restore_results.insert(tk.END, "Restore results will appear here...\n", "info")
    
    def select_source_dir(self):
        dir_path = filedialog.askdirectory(initialdir=self.source_dir)
        if dir_path:
            self.source_dir = dir_path
            self.source_dir_label.config(text=f"Source: {self.source_dir}")
    
    def select_backup_dir(self):
        dir_path = filedialog.askdirectory(initialdir=self.backup_dir)
        if dir_path:
            self.backup_dir = dir_path
            self.backup_dir_label.config(text=f"Backup: {self.backup_dir}")
            self.refresh_backup_list()
    
    def select_system_dir_scan(self):
        dir_path = filedialog.askdirectory(initialdir=self.source_dir)
        if dir_path:
            self.source_dir = dir_path
            self.system_dir_label.config(text=f"System: {self.source_dir}")
    
    def select_backup_dir_scan(self):
        dir_path = filedialog.askdirectory(initialdir=self.backup_dir)
        if dir_path:
            self.default_backup = dir_path
            self.scan_backup_label.config(text=f"Backup: {self.default_backup}")
    
    def select_custom_backup(self):
        dir_path = filedialog.askdirectory(initialdir=self.backup_dir)
        if dir_path:
            self.default_backup = dir_path
            self.custom_backup_label.config(text=f"Custom Backup: {self.default_backup}")
    
    def select_restore_target(self):
        dir_path = filedialog.askdirectory(initialdir=self.source_dir)
        if dir_path:
            self.restore_target_dir = dir_path
            self.restore_target_label.config(text=f"Restore Target: {self.restore_target_dir}")
    
    def create_backup(self):
        backup_name = self.backup_name_entry.get().strip()
        if not backup_name:
            messagebox.showerror("Error", "Backup name is required!")
            return
        
        destination = os.path.join(self.backup_dir, backup_name)
        
        # Create parameters for PowerShell script
        params = {
            "operation": "backup",
            "source_dir": self.source_dir,
            "destination_dir": destination
        }
        
        self.run_powershell_script(params)
    
    def quick_scan(self):
        if not os.path.exists(self.source_dir):
            messagebox.showerror("Error", "System directory does not exist!")
            return
        
        if not os.path.exists(self.default_backup):
            messagebox.showerror("Error", "Backup directory does not exist!")
            return
        
        # Clear previous results
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, "Scanning... Please wait...\n", "info")
        self.root.update()
        
        # Create parameters for PowerShell script
        params = {
            "operation": "scan",
            "system_dir": self.source_dir,
            "backup_dir": self.default_backup
        }
        
        self.run_powershell_script(params)
    
    def refresh_backup_list(self):
        self.backup_listbox.delete(0, tk.END)
        if not os.path.exists(self.backup_dir):
            return
        
        backups = [name for name in os.listdir(self.backup_dir) 
                  if os.path.isdir(os.path.join(self.backup_dir, name))]
        
        for backup in sorted(backups):
            self.backup_listbox.insert(tk.END, backup)
    
    def restore_backup(self):
        # Determine which backup to use (selected from list or custom)
        selected = self.backup_listbox.curselection()
        backup_path = ""
        
        if selected:
            backup_name = self.backup_listbox.get(selected[0])
            backup_path = os.path.join(self.backup_dir, backup_name)
        else:
            backup_path = self.default_backup
        
        if not backup_path or not os.path.exists(backup_path):
            messagebox.showerror("Error", "Please select a valid backup to restore")
            return
        
        if not self.restore_target_dir:
            messagebox.showerror("Error", "Please select a restore target directory")
            return
        
        # Clear previous results
        self.restore_results.delete(1.0, tk.END)
        self.restore_results.insert(tk.END, f"Preparing to restore from:\n{backup_path}\nto:\n{self.restore_target_dir}\n\n", "info")
        self.root.update()
        
        # Create parameters for PowerShell script
        params = {
            "operation": "restore",
            "backup_dir": backup_path,
            "system_dir": self.restore_target_dir
        }
        
        self.run_powershell_script(params)
    
    def run_powershell_script(self, params):
        """Run the PowerShell script with the given parameters"""
        try:
            # Save parameters to a temporary JSON file
            temp_json = os.path.join(os.environ['TEMP'], 'backup_params.json')
            with open(temp_json, 'w') as f:
                json.dump(params, f)
            
            # Get the path to the PowerShell script
            script_path = os.path.join(os.path.dirname(__file__), "backup_operations.ps1")
            
            # Build the PowerShell command
            command = [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-File", script_path,
                "-ParametersFile", temp_json
            ]
            
            self.update_status(f"Running {params['operation']} operation...")
            
            # For scan and restore operations, show real-time output
            if params['operation'] in ['scan', 'restore']:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Determine which text widget to use
                if params['operation'] == 'scan':
                    output_widget = self.scan_results
                else:
                    output_widget = self.restore_results
                
                # Clear previous results
                output_widget.delete(1.0, tk.END)
                
                # Read output line by line
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        # Determine message type for coloring
                        if "DATABREACH" in output or "Error:" in output or "ERROR:" in output:
                            tag = "error"
                        elif "Warning:" in output:
                            tag = "warning"
                        elif "successful" in output or "complete" in output or "No differences" in output:
                            tag = "success"
                        else:
                            tag = "info"
                        
                        output_widget.insert(tk.END, output, tag)
                        output_widget.see(tk.END)
                        self.root.update()
                
                # Check for errors
                stderr = process.stderr.read()
                if stderr:
                    output_widget.insert(tk.END, f"\nERROR: {stderr}\n", "error")
                
            else:
                # For other operations, just show completion message
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if process.returncode == 0:
                    messagebox.showinfo("Success", f"{params['operation'].capitalize()} completed successfully!")
                    self.update_status("Operation completed successfully")
                    
                    # Refresh backup list if it was a backup operation
                    if params['operation'] == 'backup':
                        self.refresh_backup_list()
                else:
                    messagebox.showerror("Error", f"Operation failed:\n{process.stderr}")
                    self.update_status("Operation failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run operation: {str(e)}")
            self.update_status("Error running operation")
            if params['operation'] in ['scan', 'restore']:
                if params['operation'] == 'scan':
                    self.scan_results.insert(tk.END, f"\nERROR: {str(e)}\n", "error")
                else:
                    self.restore_results.insert(tk.END, f"\nERROR: {str(e)}\n", "error")

if __name__ == "__main__":
    root = tk.Tk()
    app = BackupApp(root)
    root.mainloop()