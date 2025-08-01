import os
import hashlib
import customtkinter as ctk
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import time
from tkinter import filedialog, messagebox
import tempfile
import json
import psutil
import gc

"""
Comments are done by Claude.ai and can therefore be incorrect, the code works fine 
"""

class FolderComparisonApp:
    """
    Folder comparison tool.
    Performs READ-ONLY operations on both source and target folders.
    Only writes to the specified output file or temp folder for interim data.
    """
    def __init__(self):
        # Configure CustomTkinter appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize main window
        self.root = ctk.CTk()
        self.root.title("Folder Comparison Tool")
        self.root.geometry("800x600")
        self.root.minsize(600, 500)
        
        # Threading and progress tracking
        self.progress_queue = queue.Queue()
        self.cancel_flag = threading.Event()
        self.is_running = False
        
        # File hashes storage
        self.source_hashes = {}
        self.target_hashes = {}
        
        # Logging and statistics
        self.logging_enabled = False
        self.log_file_path = ""
        self.start_time = 0
        self.start_memory = 0
        self.files_processed = 0
        self.files_skipped = 0
        self.files_with_errors = 0
        self.error_log = []
        self.temp_files_created = []
        
        # Setup GUI
        self.setup_gui()
        
        # Start progress monitoring
        self.monitor_progress()
        
    def setup_gui(self):
        # Create scrollable frame
        self.scrollable_frame = ctk.CTkScrollableFrame(self.root)
        self.scrollable_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        title_label = ctk.CTkLabel(self.scrollable_frame, text="Folder Comparison Tool", 
                                 font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(20, 30))
        
        # Source folder selection
        source_frame = ctk.CTkFrame(self.scrollable_frame)
        source_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(source_frame, text="Original Folder:", 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        source_input_frame = ctk.CTkFrame(source_frame)
        source_input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.source_entry = ctk.CTkEntry(source_input_frame, placeholder_text="Select the original folder to compare against...")
        self.source_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ctk.CTkButton(source_input_frame, text="Browse", width=80,
                     command=self.browse_source_folder).pack(side="right")
        
        # Target folder selection
        target_frame = ctk.CTkFrame(self.scrollable_frame)
        target_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(target_frame, text="New Folder:", 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        target_input_frame = ctk.CTkFrame(target_frame)
        target_input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.target_entry = ctk.CTkEntry(target_input_frame, placeholder_text="Select the duplicated and changed folder to be compared with...")
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ctk.CTkButton(target_input_frame, text="Browse", width=80,
                     command=self.browse_target_folder).pack(side="right")
        
        # Output file selection
        output_frame = ctk.CTkFrame(self.scrollable_frame)
        output_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(output_frame, text="Output File:", 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        output_input_frame = ctk.CTkFrame(output_frame)
        output_input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.output_entry = ctk.CTkEntry(output_input_frame, placeholder_text="Select output file (result.txt)...")
        self.output_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ctk.CTkButton(output_input_frame, text="Browse", width=80,
                     command=self.browse_output_file).pack(side="right")
        
        # Options frame
        options_frame = ctk.CTkFrame(self.scrollable_frame)
        options_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(options_frame, text="Options:", 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Checkboxes
        checkbox_frame = ctk.CTkFrame(options_frame)
        checkbox_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.append_var = ctk.BooleanVar(value=False)
        self.append_checkbox = ctk.CTkCheckBox(checkbox_frame, text="Append to existing file (instead of overwrite)", 
                                             variable=self.append_var)
        self.append_checkbox.pack(anchor="w", padx=10, pady=5)
        
        self.prefix_var = ctk.BooleanVar(value=True)
        self.prefix_checkbox = ctk.CTkCheckBox(checkbox_frame, text="Include prefixes (changed:, added:, removed:)", 
                                             variable=self.prefix_var)
        self.prefix_checkbox.pack(anchor="w", padx=10, pady=5)
        
        self.logging_var = ctk.BooleanVar(value=False)
        self.logging_checkbox = ctk.CTkCheckBox(checkbox_frame, text="Enable logging (creates log.log in output folder)", 
                                              variable=self.logging_var)
        self.logging_checkbox.pack(anchor="w", padx=10, pady=5)
        
        # Performance settings
        perf_frame = ctk.CTkFrame(self.scrollable_frame)
        perf_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(perf_frame, text="Performance Settings:", 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        perf_input_frame = ctk.CTkFrame(perf_frame)
        perf_input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        ctk.CTkLabel(perf_input_frame, text="Thread Count:").pack(side="left", padx=(0, 10))
        self.thread_count = ctk.CTkEntry(perf_input_frame, width=100, placeholder_text=str(os.cpu_count()))
        self.thread_count.pack(side="left", padx=(0, 20))
        
        ctk.CTkLabel(perf_input_frame, text="Chunk Size (MB):").pack(side="left", padx=(0, 10))
        self.chunk_size = ctk.CTkEntry(perf_input_frame, width=100, placeholder_text="64")
        self.chunk_size.pack(side="left")
        
        # Progress section
        progress_frame = ctk.CTkFrame(self.scrollable_frame)
        progress_frame.pack(fill="x", padx=20, pady=10)
        
        self.progress_bar = ctk.CTkProgressBar(progress_frame)
        self.progress_bar.pack(fill="x", padx=10, pady=10)
        self.progress_bar.set(0)
        
        self.status_label = ctk.CTkLabel(progress_frame, text="Ready to compare folders")
        self.status_label.pack(pady=(0, 10))
        
        # Control buttons
        button_frame = ctk.CTkFrame(self.scrollable_frame)
        button_frame.pack(fill="x", padx=20, pady=20)
        
        self.start_button = ctk.CTkButton(button_frame, text="Start Comparison", 
                                        command=self.start_comparison, height=40,
                                        font=ctk.CTkFont(size=16, weight="bold"))
        self.start_button.pack(side="left", expand=True, fill="x", padx=(10, 5))
        
        self.cancel_button = ctk.CTkButton(button_frame, text="Cancel", 
                                         command=self.cancel_comparison, height=40,
                                         state="disabled")
        self.cancel_button.pack(side="right", expand=True, fill="x", padx=(5, 10))
        
    def browse_source_folder(self):
        folder = filedialog.askdirectory(title="Select Source Folder (Original)")
        if folder:
            self.source_entry.delete(0, 'end')
            self.source_entry.insert(0, folder)
            
    def browse_target_folder(self):
        folder = filedialog.askdirectory(title="Select Target Folder (New)")
        if folder:
            self.target_entry.delete(0, 'end')
            self.target_entry.insert(0, folder)
            
    def browse_output_file(self):
        file = filedialog.asksaveasfilename(
            title="Select Output File",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file:
            self.output_entry.delete(0, 'end')
            self.output_entry.insert(0, file)
    
    def get_file_hash(self, filepath, chunk_size_mb=64):
        """Calculate SHA-256 hash of a file efficiently"""
        hash_sha256 = hashlib.sha256()
        chunk_size = chunk_size_mb * 1024 * 1024  # Convert MB to bytes
        
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(chunk_size):
                    if self.cancel_flag.is_set():
                        return None
                    hash_sha256.update(chunk)
            self.files_processed += 1
            return hash_sha256.hexdigest()
        except (IOError, OSError, PermissionError) as e:
            error_msg = f"Error reading file {filepath}: {e}"
            print(error_msg)
            self.files_with_errors += 1
            self.error_log.append(error_msg)
            return None
        except Exception as e:
            error_msg = f"Unexpected error processing file {filepath}: {e}"
            print(error_msg)
            self.files_with_errors += 1
            self.error_log.append(error_msg)
            return None
    
    def scan_folder(self, folder_path, max_workers=None, chunk_size_mb=64):
        """Scan folder and calculate hashes for all files - READ-ONLY operation"""
        if max_workers is None:
            max_workers = os.cpu_count()
            
        file_hashes = {}
        files_to_process = []
        
        # Collect all files first
        for root, dirs, files in os.walk(folder_path):
            if self.cancel_flag.is_set():
                return {}
                
            for file in files:
                filepath = os.path.join(root, file)
                files_to_process.append(filepath)
        
        total_files = len(files_to_process)
        processed_files = 0
        
        # Process files in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all hash calculation tasks
            future_to_file = {
                executor.submit(self.get_file_hash, filepath, chunk_size_mb): filepath 
                for filepath in files_to_process
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                if self.cancel_flag.is_set():
                    executor.shutdown(wait=False)
                    return {}
                    
                filepath = future_to_file[future]
                try:
                    file_hash = future.result()
                    if file_hash:
                        # Store relative path as key
                        rel_path = os.path.relpath(filepath, folder_path)
                        file_hashes[rel_path] = {
                            'hash': file_hash,
                            'full_path': filepath
                        }
                    else:
                        # File was skipped due to error or cancellation
                        if not self.cancel_flag.is_set():
                            self.files_skipped += 1
                    
                    processed_files += 1
                    progress = processed_files / total_files
                    self.progress_queue.put(('progress', progress, f"Processing: {processed_files}/{total_files} files"))
                    
                except Exception as e:
                    print(f"Error processing {filepath}: {e}")
                    
        return file_hashes
    
    def init_logging(self, output_path):
        """Initialize logging if enabled"""
        self.logging_enabled = self.logging_var.get()
        if self.logging_enabled:
            output_dir = os.path.dirname(output_path)
            self.log_file_path = os.path.join(output_dir, "log.log")
            self.start_time = time.time()
            self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            self.files_processed = 0
            self.files_skipped = 0
            self.files_with_errors = 0
            self.error_log = []
    
    def write_log(self, changed_files, added_files, removed_files):
        """Write comprehensive log file"""
        if not self.logging_enabled:
            return
            
        try:
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            total_time = end_time - self.start_time
            memory_used = end_memory - self.start_memory
            peak_memory = psutil.Process().memory_info().peak_wss / 1024 / 1024 if hasattr(psutil.Process().memory_info(), 'peak_wss') else end_memory
            
            total_differences = len(changed_files) + len(added_files) + len(removed_files)
            
            with open(self.log_file_path, 'w', encoding='utf-8') as log_file:
                log_file.write(f"=== Folder Comparison Log ===\n")
                log_file.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.start_time))}\n")
                log_file.write(f"Source Folder: {self.source_entry.get()}\n")
                log_file.write(f"Target Folder: {self.target_entry.get()}\n")
                log_file.write(f"Output File: {self.output_entry.get()}\n\n")
                
                log_file.write(f"=== Performance Metrics ===\n")
                log_file.write(f"Total Processing Time: {total_time:.2f} seconds\n")
                log_file.write(f"Memory Usage Start: {self.start_memory:.2f} MB\n")
                log_file.write(f"Memory Usage End: {end_memory:.2f} MB\n")
                log_file.write(f"Memory Usage Delta: {memory_used:.2f} MB\n")
                log_file.write(f"Peak Memory Usage: {peak_memory:.2f} MB\n\n")
                
                log_file.write(f"=== File Statistics ===\n")
                log_file.write(f"Files Successfully Processed: {self.files_processed}\n")
                log_file.write(f"Files Skipped: {self.files_skipped}\n")
                log_file.write(f"Files with Errors: {self.files_with_errors}\n")
                log_file.write(f"Total Files in Source: {len(self.source_hashes)}\n")
                log_file.write(f"Total Files in Target: {len(self.target_hashes)}\n")
                log_file.write(f"Files Changed: {len(changed_files)}\n")
                log_file.write(f"Files Added: {len(added_files)}\n")
                log_file.write(f"Files Removed: {len(removed_files)}\n")
                log_file.write(f"Total Differences: {total_differences}\n\n")
                
                if self.error_log:
                    log_file.write(f"=== Error Details ===\n")
                    for error in self.error_log:
                        log_file.write(f"{error}\n")
                    log_file.write("\n")
                
                log_file.write(f"=== Configuration ===\n")
                try:
                    thread_count = int(self.thread_count.get() or os.cpu_count())
                except ValueError:
                    thread_count = os.cpu_count()
                try:
                    chunk_size = int(self.chunk_size.get() or 64)
                except ValueError:
                    chunk_size = 64
                    
                log_file.write(f"Thread Count: {thread_count}\n")
                log_file.write(f"Chunk Size: {chunk_size} MB\n")
                log_file.write(f"Hash Algorithm: SHA-256\n")
                log_file.write(f"Append Mode: {self.append_var.get()}\n")
                log_file.write(f"Prefix Mode: {self.prefix_var.get()}\n")
                log_file.write(f"Logging Enabled: {self.logging_enabled}\n")
                
        except Exception as e:
            print(f"Error writing log file: {e}")
    
    def cleanup_temp_files(self):
        """Clean up any temporary files created during processing"""
        for temp_file in self.temp_files_created:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    print(f"Cleaned up temp file: {temp_file}")
            except Exception as e:
                print(f"Error cleaning up temp file {temp_file}: {e}")
        self.temp_files_created.clear()
        
        # Force garbage collection to free memory
        gc.collect()
    
    def compare_folders(self):
        """Main comparison logic running in separate thread - READ-ONLY operations on both folders"""
        try:
            source_path = self.source_entry.get().strip()
            target_path = self.target_entry.get().strip()
            output_path = self.output_entry.get().strip()
            
            if not all([source_path, target_path, output_path]):
                self.progress_queue.put(('error', "Please select all required paths"))
                return
                
            if not os.path.exists(source_path):
                self.progress_queue.put(('error', f"Source folder does not exist: {source_path}"))
                return
                
            if not os.path.exists(target_path):
                self.progress_queue.put(('error', f"Target folder does not exist: {target_path}"))
                return
            
            # Initialize logging
            self.init_logging(output_path)
            
            # Get performance settings
            try:
                max_workers = int(self.thread_count.get() or os.cpu_count())
            except ValueError:
                max_workers = os.cpu_count()
                
            try:
                chunk_size_mb = int(self.chunk_size.get() or 64)
            except ValueError:
                chunk_size_mb = 64
            
            self.progress_queue.put(('status', "Scanning source folder..."))
            self.source_hashes = self.scan_folder(source_path, max_workers, chunk_size_mb)
            
            if self.cancel_flag.is_set():
                self.cleanup_temp_files()
                return
                
            self.progress_queue.put(('status', "Scanning target folder..."))
            self.target_hashes = self.scan_folder(target_path, max_workers, chunk_size_mb)
            
            if self.cancel_flag.is_set():
                self.cleanup_temp_files()
                return
                
            self.progress_queue.put(('status', "Comparing folders..."))
            
            # Find differences
            changed_files = []
            added_files = []
            removed_files = []
            
            # Check for changed and removed files
            for rel_path, source_info in self.source_hashes.items():
                if rel_path in self.target_hashes:
                    if source_info['hash'] != self.target_hashes[rel_path]['hash']:
                        changed_files.append(self.target_hashes[rel_path]['full_path'])
                else:
                    removed_files.append(source_info['full_path'])
            
            # Check for added files
            for rel_path, target_info in self.target_hashes.items():
                if rel_path not in self.source_hashes:
                    added_files.append(target_info['full_path'])
            
            # Write results
            self.progress_queue.put(('status', "Writing results..."))
            self.write_results(output_path, changed_files, added_files, removed_files)
            
            # Write log if enabled
            if self.logging_enabled:
                self.progress_queue.put(('status', "Writing log file..."))
                self.write_log(changed_files, added_files, removed_files)
            
            # Clean up
            self.cleanup_temp_files()
            
            total_differences = len(changed_files) + len(added_files) + len(removed_files)
            log_msg = f" (log: {self.log_file_path})" if self.logging_enabled else ""
            self.progress_queue.put(('complete', f"Comparison complete! Found {total_differences} differences.{log_msg}"))
            
        except Exception as e:
            self.cleanup_temp_files()
            self.progress_queue.put(('error', f"Comparison failed: {str(e)}"))
    
    def write_results(self, output_path, changed_files, added_files, removed_files):
        """Write comparison results to output file"""
        mode = 'a' if self.append_var.get() else 'w'
        use_prefixes = self.prefix_var.get()
        
        try:
            with open(output_path, mode, encoding='utf-8') as f:
                if self.append_var.get():
                    f.write(f"\n\n--- Comparison Results {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                
                # Write all files in the order: changed, added, removed
                all_results = []
                
                if use_prefixes:
                    for file_path in changed_files:
                        all_results.append(f'changed: "{file_path}"')
                    for file_path in added_files:
                        all_results.append(f'added: "{file_path}"')
                    for file_path in removed_files:
                        all_results.append(f'removed: "{file_path}"')
                else:
                    for file_path in changed_files + added_files + removed_files:
                        all_results.append(f'"{file_path}"')
                
                for result in all_results:
                    f.write(result + '\n')
                    
        except Exception as e:
            self.progress_queue.put(('error', f"Error writing results: {str(e)}"))
    
    def start_comparison(self):
        """Start the comparison process"""
        if self.is_running:
            return
            
        self.is_running = True
        self.cancel_flag.clear()
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.progress_bar.set(0)
        
        # Start comparison in separate thread
        comparison_thread = threading.Thread(target=self.compare_folders, daemon=True)
        comparison_thread.start()
    
    def cancel_comparison(self):
        """Cancel the ongoing comparison"""
        self.cancel_flag.set()
        self.progress_queue.put(('status', "Cancelling..."))
    
    def monitor_progress(self):
        """Monitor progress queue and update GUI"""
        try:
            while True:
                msg_type, *args = self.progress_queue.get_nowait()
                
                if msg_type == 'progress':
                    progress, status = args
                    self.progress_bar.set(progress)
                    self.status_label.configure(text=status)
                    
                elif msg_type == 'status':
                    status = args[0]
                    self.status_label.configure(text=status)
                    
                elif msg_type == 'complete':
                    message = args[0]
                    self.status_label.configure(text=message)
                    self.progress_bar.set(1.0)
                    self.reset_buttons()
                    messagebox.showinfo("Success", message)
                    
                elif msg_type == 'error':
                    error_msg = args[0]
                    self.status_label.configure(text=f"Error: {error_msg}")
                    self.reset_buttons()
                    messagebox.showerror("Error", error_msg)
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.monitor_progress)
    
    def reset_buttons(self):
        """Reset button states after operation"""
        self.is_running = False
        self.start_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = FolderComparisonApp()
    app.run()