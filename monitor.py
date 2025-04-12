import os
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Monitor")
        self.root.geometry("600x400")
        
        # Variables
        self.monitoring = False  # Will be set to True when monitoring starts
        self.observer = None
        self.watch_path = tk.StringVar(value=r"D:/ ")
        
        # Create UI
        self.create_widgets()
        
        # Start monitoring automatically
        self.start_monitoring()
        
    def create_widgets(self):
        # Path selection frame
        path_frame = ttk.LabelFrame(self.root, text="Monitor Directory")
        path_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(path_frame, text="Directory:").pack(side="left", padx=5)
        
        self.path_entry = ttk.Entry(path_frame, textvariable=self.watch_path, width=50)
        self.path_entry.pack(side="left", expand=True, fill="x", padx=5)
        
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse_directory)
        browse_btn.pack(side="left", padx=5)
        
        # Control buttons frame
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=5, fill="x")
        
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", state="disabled")
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_btn.pack(side="left", padx=5)
        
        # Log frame
        log_frame = ttk.LabelFrame(self.root, text="Activity Log")
        log_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=60, height=15)
        self.log_text.pack(pady=5, padx=5, fill="both", expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken")
        status_bar.pack(side="bottom", fill="x")
    
    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.watch_path.set(directory)
            # Restart monitoring with new directory
            self.stop_monitoring()
            self.start_monitoring()
    
    def log_message(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.update()
    
    def start_monitoring(self):
        path = self.watch_path.get().strip()
        
        if not path:
            self.log_message("Error: No directory specified")
            return
            
        if not os.path.isdir(path):
            self.log_message(f"Error: Directory not found - {path}")
            return
            
        if self.monitoring:
            self.stop_monitoring()
            
        self.event_handler = FileEventHandler(self)
        self.observer = Observer()
        
        try:
            self.observer.schedule(self.event_handler, path, recursive=True)
            self.observer.start()
            self.monitoring = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.status_var.set(f"Monitoring: {path}")
            self.log_message(f"Started monitoring directory: {path}")
            self.log_message("Watching for file changes...")
        except Exception as e:
            self.log_message(f"Error starting monitor: {str(e)}")
    
    def stop_monitoring(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join()
                self.log_message("Monitoring stopped")
            except Exception as e:
                self.log_message(f"Error stopping monitor: {str(e)}")
            finally:
                self.observer = None
                
        self.monitoring = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Monitoring stopped")
    
    def on_closing(self):
        self.stop_monitoring()
        self.root.destroy()

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, gui):
        super().__init__()
        self.gui = gui
    
    def on_created(self, event):
        self.gui.log_message(f"Created: {event.src_path}")
    
    def on_deleted(self, event):
        self.gui.log_message(f"Deleted: {event.src_path}")
    
    def on_modified(self, event):
        self.gui.log_message(f"Modified: {event.src_path}")
    
    def on_moved(self, event):
        self.gui.log_message(f"Moved: {event.src_path} -> {event.dest_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileMonitorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()