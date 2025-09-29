#!/usr/bin/env python3
"""
AI-Powered Vulnerability Scanner GUI
A comprehensive tool that uses AI to predict vulnerabilities from scan results.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import subprocess
import json
from datetime import datetime
from typing import List, Dict
import sys
import os

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import your scanning engine
try:
    from nmap_parser import run_nmap, parse_nmap_xml
    from gobuster_parser import run_gobuster, parse_gobuster_output
    from nikto_parser import run_nikto, parse_nikto_output
except ImportError:
    print("Warning: Scanning modules not found. Using simulation mode.")
    # Create dummy functions for simulation
    def run_nmap(target, nmap_arguments="-sV -O"):
        print(f"Simulating Nmap scan on {target} with {nmap_arguments}")
        return f"data/{target}_nmap.xml"
    
    def parse_nmap_xml(xml_file):
        return {"port_21_open": 1, "port_22_open": 1, "total_open_ports": 3}
    
    def run_gobuster(target, gobuster_arguments="dir -w /usr/share/wordlists/dirb/common.txt"):
        print(f"Simulating Gobuster scan on {target} with {gobuster_arguments}")
        return f"data/{target}_gobuster.txt"
    
    def parse_gobuster_output(output_file):
        return {"count_path_200": 2, "path_contains_admin": 1}
    
    def run_nikto(target, nikto_arguments=""):
        print(f"Simulating Nikto scan on {target} with {nikto_arguments}")
        return f"data/{target}_nikto.txt"
    
    def parse_nikto_output(output_file):
        return {"nikto_high_risk_findings": 1, "nikto_found_xss": 1}

# Set appearance mode and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class AIVulnerabilityScanner:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("AI-Powered Vulnerability Scanner")
        self.window.geometry("1200x800")
        self.window.configure(fg_color="#1a1a1a")
        
        # State variables
        self.current_tab = "scan"
        self.scanning = False
        self.selected_tools = []
        
        # Scan history
        self.scan_history = [
            {"target": "192.168.56.102", "status": "Completed", "tools": ["Nmap", "Gobuster", "Nikto"], "date": "2024-01-15 14:30", "prediction": "High Risk (CVSS: 8.2)"},
            {"target": "example.com", "status": "Completed", "tools": ["Nmap"], "date": "2024-01-15 15:45", "prediction": "Low Risk (CVSS: 2.1)"}
        ]
        
        self.setup_ui()
        self.show_tab("scan")
        
    def setup_ui(self):
        """Setup the main UI components"""
        # Create main container
        self.main_frame = ctk.CTkFrame(self.window, fg_color="#2b2b2b", corner_radius=10)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Window controls frame
        self.create_window_controls()
        
        # Content frame
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Sidebar
        self.create_sidebar()
        
        # Main content area
        self.main_content = ctk.CTkFrame(self.content_frame, fg_color="#1a1a1a")
        self.main_content.pack(side="right", fill="both", expand=True, padx=(0, 0))
        
    def create_window_controls(self):
        """Create macOS-style title bar without duplicate controls"""
        controls_frame = ctk.CTkFrame(self.main_frame, height=40, fg_color="#404040")
        controls_frame.pack(fill="x", padx=0, pady=0)
        controls_frame.pack_propagate(False)
    
        # Title in the center (or left)
        title_label = ctk.CTkLabel(controls_frame, text="AI Vulnerability Scanner", 
                                text_color="#ffffff", font=("Arial", 12, "bold"))
        title_label.pack(side="left", padx=15, pady=10)
    
        # Status indicator
        self.status_label = ctk.CTkLabel(controls_frame, text="Ready", text_color="#88ff88")
        self.status_label.pack(side="right", padx=15, pady=10)
        
    def create_sidebar(self):
        """Create the navigation sidebar"""
        self.sidebar = ctk.CTkFrame(self.content_frame, width=200, fg_color="#333333")
        self.sidebar.pack(side="left", fill="y", padx=(0, 2))
        self.sidebar.pack_propagate(False)
        
        # Menu items
        menu_items = [
            ("scan", "Scan", "🔍"),
            ("history", "History", "📝"),
            ("settings", "Settings", "⚙️"),
            ("about", "About", "ℹ️")
        ]
        
        for item_id, label, icon in menu_items:
            btn = ctk.CTkButton(
                self.sidebar, 
                text=f"{icon} {label}",
                anchor="w",
                height=40,
                fg_color="#333333" if item_id != self.current_tab else "#00aa00",
                hover_color="#444444",
                command=lambda x=item_id: self.show_tab(x)
            )
            btn.pack(fill="x", padx=10, pady=2)
            
    def show_tab(self, tab_name):
        """Switch between different tabs"""
        self.current_tab = tab_name
        
        # Clear main content
        for widget in self.main_content.winfo_children():
            widget.destroy()
            
        # Update sidebar buttons
        for widget in self.sidebar.winfo_children():
            if isinstance(widget, ctk.CTkButton):
                if tab_name in widget.cget("text").lower():
                    widget.configure(fg_color="#00aa00")
                else:
                    widget.configure(fg_color="#333333")
        
        # Show appropriate content
        if tab_name == "scan":
            self.create_scanning_interface()
        elif tab_name == "history":
            self.create_history_interface()
        elif tab_name == "settings":
            self.create_settings_interface()
        elif tab_name == "about":
            self.create_about_interface()
            
    def create_scanning_interface(self):
        """Create the main scanning interface"""
        # Scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(self.main_content)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Target input
        ctk.CTkLabel(scroll_frame, text="Target", font=("Arial", 16, "bold")).pack(anchor="w", pady=(0, 5))
        self.target_entry = ctk.CTkEntry(scroll_frame, placeholder_text="Enter target IP or domain...")
        self.target_entry.pack(fill="x", pady=(0, 20))

        # Tool selection
        ctk.CTkLabel(scroll_frame, text="Tools", font=("Arial", 16, "bold")).pack(anchor="w", pady=(0, 10))

        tools_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        tools_frame.pack(fill="x", pady=(0, 20))

        self.tool_vars = {}
        tools = ["Nmap", "Gobuster", "Nikto"]

        for i, tool in enumerate(tools):
            var = tk.BooleanVar()
            self.tool_vars[tool] = var
            checkbox = ctk.CTkCheckBox(tools_frame, text=tool, variable=var,
                                    command=self.toggle_tool_options)
            checkbox.grid(row=i//2, column=i%2, sticky="w", padx=10, pady=5)

        # --- Nmap Arguments Section ---
        self.nmap_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        self.nmap_label = ctk.CTkLabel(self.nmap_frame, text="Nmap Arguments", font=("Arial", 14, "bold"))
        self.nmap_label.pack(anchor="w", padx=15, pady=(10, 5))

        # Pre-defined Nmap scan types
        nmap_presets = [
            "Quick Scan (-T4 -F)",
            "Service Detection (-sV)",
            "OS Detection (-O)",
            "Stealth Scan (-sS)",
            "UDP Scan (-sU)",
            "Comprehensive (-sS -sV -O --script vuln)",
            "Custom (enter below)"
        ]

        self.nmap_preset_var = ctk.StringVar(value="Service Detection (-sV)")
        nmap_preset_combo = ctk.CTkComboBox(self.nmap_frame, variable=self.nmap_preset_var, values=nmap_presets,
                                        command=self.on_nmap_preset_change)
        nmap_preset_combo.pack(fill="x", padx=15, pady=(0, 5))

        self.nmap_custom_entry = ctk.CTkEntry(self.nmap_frame, placeholder_text="Or enter custom Nmap arguments...")
        self.nmap_custom_entry.pack(fill="x", padx=15, pady=(0, 10))
        self.nmap_custom_entry.insert(0, "-sV -O")  # Default
        
        # Initially hide Nmap options
        self.nmap_frame.pack_forget()
        
        # --- Gobuster Wordlist Section ---
        self.gobuster_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        self.gobuster_label = ctk.CTkLabel(self.gobuster_frame, text="Gobuster Wordlist", font=("Arial", 14, "bold"))
        self.gobuster_label.pack(anchor="w", padx=15, pady=(10, 5))
        
        # Common wordlist options
        wordlist_frame = ctk.CTkFrame(self.gobuster_frame, fg_color="transparent")
        wordlist_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        self.wordlist_var = ctk.StringVar(value="/usr/share/wordlists/dirb/common.txt")
        wordlist_options = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirb/big.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
            "Custom wordlist..."
        ]
        
        wordlist_combo = ctk.CTkComboBox(wordlist_frame, variable=self.wordlist_var, values=wordlist_options,
                                        command=self.on_wordlist_change)
        wordlist_combo.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.browse_wordlist_btn = ctk.CTkButton(wordlist_frame, text="Browse", width=80,
                                                command=self.browse_wordlist)
        self.browse_wordlist_btn.pack(side="right")
        
        self.custom_wordlist_entry = ctk.CTkEntry(self.gobuster_frame, placeholder_text="Enter custom wordlist path...")
        self.custom_wordlist_entry.pack(fill="x", padx=15, pady=(0, 10))
        self.custom_wordlist_entry.pack_forget()  # Initially hidden
        
        # Initially hide Gobuster options
        self.gobuster_frame.pack_forget()
        
        # --- Nikto Options Section ---
        self.nikto_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        self.nikto_label = ctk.CTkLabel(self.nikto_frame, text="Nikto Options", font=("Arial", 14, "bold"))
        self.nikto_label.pack(anchor="w", padx=15, pady=(10, 5))
        
        # Nikto tuning options
        nikto_options_frame = ctk.CTkFrame(self.nikto_frame, fg_color="transparent")
        nikto_options_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(nikto_options_frame, text="Scan tuning:").pack(side="left")
        
        self.nikto_tuning_var = ctk.StringVar(value="Default")
        nikto_tuning_combo = ctk.CTkComboBox(nikto_options_frame, variable=self.nikto_tuning_var,
                                            values=["Default", "Scan everything (0)", "File upload (1)", "Interesting files (2)",
                                                "Information disclosure (3)", "Injection (4)", "Remote file retrieval (5)",
                                                "Command execution (6)", "SQL injection (7)", "File inclusion (8)",
                                                "Remote code execution (9)", "Authentication bypass (a)"])
        nikto_tuning_combo.pack(side="left", padx=(10, 0))
        
        # Initially hide Nikto options
        self.nikto_frame.pack_forget()

        # --- Control buttons ---
        button_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=20)
        
        self.start_btn = ctk.CTkButton(
            button_frame, 
            text="▶ Start Scan", 
            fg_color="#00aa00",
            hover_color="#008800",
            command=self.start_scan
        )
        self.start_btn.pack(side="left", padx=(0, 10))
        
        self.stop_btn = ctk.CTkButton(
            button_frame, 
            text="⏹ Stop", 
            fg_color="#cc4444",
            hover_color="#aa2222",
            command=self.stop_scan,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=(0, 10))
        
        export_btn = ctk.CTkButton(
            button_frame, 
            text="📄 Export PDF", 
            fg_color="#666666",
            hover_color="#555555",
            command=self.export_pdf
        )
        export_btn.pack(side="left")

        # Progress indicator
        self.progress_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        self.progress_frame.pack(fill="x", pady=(0, 20))

        self.progress_label = ctk.CTkLabel(self.progress_frame, text="Ready to scan", text_color="#888888")
        self.progress_label.pack(anchor="w")

        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, height=10)
        self.progress_bar.pack(fill="x", pady=(5, 0))
        self.progress_bar.set(0)

        # AI Results Frame
        ctk.CTkLabel(scroll_frame, text="AI Prediction", font=("Arial", 16, "bold")).pack(anchor="w", pady=(20, 5))
        
        self.ai_results_frame = ctk.CTkFrame(scroll_frame, fg_color="#1a2b1a", corner_radius=5)
        self.ai_results_frame.pack(fill="x", pady=(0, 20))
        
        self.ai_result_label = ctk.CTkLabel(
            self.ai_results_frame, 
            text="Run a scan to see AI vulnerability predictions...",
            text_color="#88ff88",
            wraplength=600
        )
        self.ai_result_label.pack(padx=15, pady=15)
            
        # Output area
        ctk.CTkLabel(scroll_frame, text="Scan Output", font=("Arial", 16, "bold")).pack(anchor="w", pady=(10, 5))
        
        self.output_text = ctk.CTkTextbox(
            scroll_frame, 
            height=200,
            font=("Courier", 12),
            fg_color="#0a0a0a",
            text_color="#00ff00"
        )
        self.output_text.pack(fill="x", pady=(0, 20))
        self.output_text.insert("1.0", "Tool output will appear here...\n")
        
    def toggle_tool_options(self):
        """Show/hide options based on selected tools"""
        # Show Nmap options if Nmap is selected
        if self.tool_vars["Nmap"].get():
            self.nmap_frame.pack(fill="x", pady=(0, 10))
        else:
            self.nmap_frame.pack_forget()
        
        # Show Gobuster options if Gobuster is selected
        if self.tool_vars["Gobuster"].get():
            self.gobuster_frame.pack(fill="x", pady=(0, 10))
        else:
            self.gobuster_frame.pack_forget()
        
        # Show Nikto options if Nikto is selected
        if self.tool_vars["Nikto"].get():
            self.nikto_frame.pack(fill="x", pady=(0, 10))
        else:
            self.nikto_frame.pack_forget()

    def on_nmap_preset_change(self, choice):
        """Handle Nmap preset selection"""
        preset_map = {
            "Quick Scan (-T4 -F)": "-T4 -F",
            "Service Detection (-sV)": "-sV",
            "OS Detection (-O)": "-O",
            "Stealth Scan (-sS)": "-sS",
            "UDP Scan (-sU)": "-sU",
            "Comprehensive (-sS -sV -O --script vuln)": "-sS -sV -O --script vuln",
            "Custom (enter below)": ""
        }
        
        if choice != "Custom (enter below)":
            self.nmap_custom_entry.delete(0, tk.END)
            self.nmap_custom_entry.insert(0, preset_map[choice])

    def on_wordlist_change(self, choice):
        """Handle wordlist selection"""
        if choice == "Custom wordlist...":
            self.custom_wordlist_entry.pack(fill="x", padx=15, pady=(0, 10))
            self.browse_wordlist_btn.configure(state="normal")
        else:
            self.custom_wordlist_entry.pack_forget()
            self.browse_wordlist_btn.configure(state="disabled")

    def browse_wordlist(self):
        """Open file dialog to browse for wordlist"""
        file_path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.custom_wordlist_entry.delete(0, tk.END)
            self.custom_wordlist_entry.insert(0, file_path)

    def start_scan(self):
        """Start the scanning process"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
            
        selected_tools = [tool for tool, var in self.tool_vars.items() if var.get()]
        if not selected_tools:
            messagebox.showerror("Error", "Please select at least one tool")
            return
        
        # Get selected options
        scan_options = {
            "nmap_args": self.nmap_custom_entry.get().strip(),
            "gobuster_wordlist": self.custom_wordlist_entry.get().strip() or self.wordlist_var.get(),
            "nikto_tuning": self.nikto_tuning_var.get()
        }
        
        self.scanning = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.ai_result_label.configure(text="Scan in progress... AI analysis pending.")
        self.status_label.configure(text="Scanning...")
        
        # Start scanning in a separate thread with options
        scan_thread = threading.Thread(target=self.run_scan, args=(target, selected_tools, scan_options))
        scan_thread.daemon = True
        scan_thread.start()

    def run_scan(self, target, tools, scan_options):
    	"""Run the actual scan using the scanning engine"""
    	self.output_text.delete("1.0", tk.END)
    	self.output_text.insert(tk.END, "Starting scan...\n")
    	self.window.update()
    
    	all_features = {}
    	scan_successful = True
    
    	try:
    	    # Run Nmap if selected
    	    if "Nmap" in tools and self.scanning:
    	        self.output_text.insert(tk.END, f"\n[+] Running Nmap with arguments: {scan_options['nmap_args']}\n")
    	        self.window.update()
    	        self.progress_bar.set(0.25)
    	        self.progress_label.configure(text="Running Nmap...")
    	        
    	        # Build the full Nmap command
    	        nmap_command = scan_options['nmap_args']
    	        xml_file = run_nmap(target, nmap_command)
            
    	        if xml_file and self.scanning:
    	            nmap_features = parse_nmap_xml(xml_file)
                
    	            # Check if nmap_features is None (parsing failed)
    	            if nmap_features is None:
    	                self.output_text.insert(tk.END, "[!] Failed to parse Nmap XML results.\n")
    	                scan_successful = False
    	            else:
    	                all_features.update(nmap_features)
                    
    	                # Show vulnerability summary
    	                vuln_text = f"[+] Nmap completed. Found {nmap_features.get('total_open_ports', 0)} open ports.\n"
    	                if nmap_features.get('critical_vuln_count', 0) > 0:
    	                    vuln_text += f"[!] CRITICAL: {nmap_features.get('critical_vuln_count', 0)} exploitable vulnerabilities found!\n"
    	                if nmap_features.get('high_vuln_count', 0) > 0:
    	                    vuln_text += f"[!] HIGH: {nmap_features.get('high_vuln_count', 0)} high-risk vulnerabilities\n"
    	                if nmap_features.get('vuln_backdoor_detected', 0) == 1:
    	                    vuln_text += "[!] BACKDOOR: vsftpd 2.3.4 backdoor detected (CVE-2011-2523)\n"
    	                if nmap_features.get('vuln_rce_detected', 0) == 1:
    	                    vuln_text += "[!] RCE: Remote code execution vulnerabilities detected\n"
    	                if nmap_features.get('vuln_sqli_detected', 0) == 1:
    	                    vuln_text += "[!] SQLi: SQL injection vulnerabilities detected\n"
                    
    	                self.output_text.insert(tk.END, vuln_text)
                
    	        else:
    	            self.output_text.insert(tk.END, "[!] Nmap scan failed or was cancelled.\n")
    	            scan_successful = False
            
    	        self.window.update()
        
    	    # Only continue with other tools if Nmap was successful
    	    if not scan_successful:
    	        self.output_text.insert(tk.END, "\n[!] Skipping remaining tools due to Nmap failure.\n")
    	        return
        
    	    # Run Gobuster if selected
    	    if "Gobuster" in tools and self.scanning and scan_successful:
    	        self.output_text.insert(tk.END, f"\n[+] Running Gobuster with wordlist: {scan_options['gobuster_wordlist']}\n")
    	        self.window.update()
    	        self.progress_bar.set(0.5)
    	        self.progress_label.configure(text="Running Gobuster...")
            
    	        # Build Gobuster command
    	        gobuster_command = f"dir -w {scan_options['gobuster_wordlist']}"
    	        output_file = run_gobuster(target, gobuster_command)
            
    	        if output_file and self.scanning:
    	            gobuster_features = parse_gobuster_output(output_file)
    	            if gobuster_features is not None:
    	                all_features.update(gobuster_features)
    	                self.output_text.insert(tk.END, f"[+] Gobuster completed. Found {gobuster_features.get('count_path_200', 0)} accessible paths.\n")
    	            else:
    	                self.output_text.insert(tk.END, "[!] Failed to parse Gobuster results.\n")
    	        else:
    	            self.output_text.insert(tk.END, "[!] Gobuster scan failed or was cancelled.\n")
            
    	        self.window.update()
        
    	    # Run Nikto if selected
    	    if "Nikto" in tools and self.scanning and scan_successful:
    	        self.output_text.insert(tk.END, f"\n[+] Running Nikto with tuning: {scan_options['nikto_tuning']}\n")
    	        self.window.update()
    	        self.progress_bar.set(0.75)
    	        self.progress_label.configure(text="Running Nikto...")
            
    	        # Nikto doesn't accept custom arguments in our current implementation
    	        output_file = run_nikto(target)  # Only pass target, no second argument
            
    	        if output_file and self.scanning:
    	            nikto_features = parse_nikto_output(output_file)
    	            if nikto_features is not None:
    	                all_features.update(nikto_features)
    	                self.output_text.insert(tk.END, f"[+] Nikto completed. Found {nikto_features.get('nikto_high_risk_findings', 0)} high-risk findings.\n")
    	            else:
    	                self.output_text.insert(tk.END, "[!] Failed to parse Nikto results.\n")
    	        else:
    	            self.output_text.insert(tk.END, "[!] Nikto scan failed or was cancelled.\n")
            
    	        self.window.update()
        
    	    if self.scanning and scan_successful:
    	        # AI PREDICTION PHASE
    	        self.output_text.insert(tk.END, "\n[+] Running AI vulnerability analysis...\n")
    	        self.window.update()
    	        self.progress_bar.set(0.9)
    	        self.progress_label.configure(text="AI Analysis...")
            
    	        # Run AI prediction
    	        ai_prediction, cvss_score = self.predict_vulnerabilities(all_features)
            
    	        # Display AI results
    	        self.ai_result_label.configure(text=ai_prediction)
            
    	        self.output_text.insert(tk.END, f"[+] AI analysis completed: {ai_prediction}\n")
    	        
    	        # === SAVE THE FEATURES TO JSON FILE ===
    	        try:
    	            import os
    	            # Create data directory if it doesn't exist
    	            os.makedirs("data", exist_ok=True)
                
    	            # Save features file
    	            features_filename = f"data/{target}_features.json"
    	            with open(features_filename, 'w') as f:
    	                json.dump(all_features, f, indent=4)
                
    	            self.output_text.insert(tk.END, f"[+] Features saved to: {features_filename}\n")
    	            print(f"Features saved to: {features_filename}")
                
    	        except Exception as e:
    	            self.output_text.insert(tk.END, f"[!] Failed to save features file: {str(e)}\n")
            
    	        self.output_text.insert(tk.END, "Scan and analysis completed successfully.\n")
            
    	        # Add to history
    	        new_scan = {
    	            "target": target,
    	            "status": "Completed",
    	            "tools": tools,
    	            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
    	            "prediction": f"{ai_prediction} (CVSS: {cvss_score})"
    	        }
    	        self.scan_history.insert(0, new_scan)
                
    	except Exception as e:
    	    self.output_text.insert(tk.END, f"\n[!] Error during scan: {str(e)}\n")
    	    import traceback
    	    self.output_text.insert(tk.END, f"Detailed error: {traceback.format_exc()}\n")
    	    scan_successful = False
    
    	finally:
    	    self.scanning = False
    	    self.start_btn.configure(state="normal")
    	    self.stop_btn.configure(state="disabled")
    	    self.progress_bar.set(1.0)
    	    self.progress_label.configure(text="Scan completed!")
    	    self.status_label.configure(text="Ready")
    	    print(f"Scan completed. Features collected: {all_features}")
        
    def predict_vulnerabilities(self, features):
        """Predict vulnerabilities based on scan features"""
        # TODO: Replace this with your trained AI model
        # This is a simple heuristic-based prediction for demonstration
        
        high_risk_indicators = 0
        
        # Check for common vulnerability indicators
        if features.get('port_21_open', 0) == 1:
            high_risk_indicators += 1  # FTP often has vulnerabilities
        if features.get('port_445_open', 0) == 1:
            high_risk_indicators += 1  # SMB often has vulnerabilities
        if features.get('version_contains_old', 0) == 1:
            high_risk_indicators += 2  # Old versions are high risk
        if features.get('nikto_high_risk_findings', 0) > 0:
            high_risk_indicators += features['nikto_high_risk_findings']
        if features.get('path_contains_admin', 0) == 1:
            high_risk_indicators += 1  # Admin paths are interesting
        
        # Simple risk assessment
        if high_risk_indicators >= 3:
            return "🔴 HIGH RISK: Multiple vulnerability indicators detected", 8.5
        elif high_risk_indicators >= 1:
            return "🟡 MEDIUM RISK: Some vulnerability indicators found", 5.2
        else:
            return "🟢 LOW RISK: No significant vulnerabilities detected", 2.1

    def stop_scan(self):
        """Stop the scanning process"""
        self.scanning = False
        self.output_text.insert(tk.END, "\nScan interrupted by user.\n")
        self.ai_result_label.configure(text="Scan cancelled. No AI analysis performed.")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.progress_label.configure(text="Scan cancelled")
        self.status_label.configure(text="Ready")
        
    def export_pdf(self):
        """Export scan results to PDF"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if file_path:
            messagebox.showinfo("Export", f"Scan results would be exported to:\n{file_path}")

    def create_history_interface(self):
        """Create scan history interface"""
        scroll_frame = ctk.CTkScrollableFrame(self.main_content)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(scroll_frame, text="Scan History", font=("Arial", 24, "bold")).pack(anchor="w", pady=(0, 20))
        
        if not self.scan_history:
            ctk.CTkLabel(scroll_frame, text="No scan history yet.", text_color="#888888").pack(anchor="w", pady=20)
            return
            
        for scan in self.scan_history:
            history_frame = ctk.CTkFrame(scroll_frame)
            history_frame.pack(fill="x", pady=5)
            
            # Main info
            info_frame = ctk.CTkFrame(history_frame, fg_color="transparent")
            info_frame.pack(fill="x", padx=15, pady=10)
            
            ctk.CTkLabel(info_frame, text=scan["target"], font=("Arial", 14, "bold")).pack(side="left")
            
            status_color = "#00aa00" if scan["status"] == "Completed" else "#0088ff"
            ctk.CTkLabel(info_frame, text=scan["status"], text_color=status_color).pack(side="right")
            
            # Details
            details_frame = ctk.CTkFrame(history_frame, fg_color="transparent")
            details_frame.pack(fill="x", padx=15, pady=(0, 5))
            
            tools_text = f"{', '.join(scan['tools'])} - {scan['date']}"
            ctk.CTkLabel(details_frame, text=tools_text, text_color="#888888").pack(side="left")
            
            # AI Prediction in history
            if "prediction" in scan:
                prediction_color = "#ff5555" if "High" in scan["prediction"] else "#ffaa00" if "Medium" in scan["prediction"] else "#55ff55"
                ctk.CTkLabel(details_frame, text=scan["prediction"], text_color=prediction_color).pack(side="right")
        
    def create_settings_interface(self):
        """Create settings interface"""
        scroll_frame = ctk.CTkScrollableFrame(self.main_content)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(scroll_frame, text="Scanner Settings", font=("Arial", 24, "bold")).pack(anchor="w", pady=(0, 20))
        
        # Nmap settings
        nmap_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        nmap_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(nmap_frame, text="Nmap Arguments", font=("Arial", 14, "bold")).pack(anchor="w", padx=15, pady=(10, 5))
        self.nmap_args_entry = ctk.CTkEntry(nmap_frame, placeholder_text="e.g., -sS -sV --script vuln")
        self.nmap_args_entry.insert(0, "-sV -O")  # Default
        self.nmap_args_entry.pack(fill="x", padx=15, pady=(0, 10))
        
        # Gobuster settings
        gobuster_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        gobuster_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(gobuster_frame, text="Gobuster Arguments", font=("Arial", 14, "bold")).pack(anchor="w", padx=15, pady=(10, 5))
        self.gobuster_args_entry = ctk.CTkEntry(gobuster_frame, placeholder_text="e.g., dir -w /path/to/wordlist.txt")
        self.gobuster_args_entry.insert(0, "dir -w /usr/share/wordlists/dirb/common.txt")  # Default
        self.gobuster_args_entry.pack(fill="x", padx=15, pady=(0, 10))
        
        # Save settings button
        save_btn = ctk.CTkButton(
            scroll_frame, 
            text="💾 Save Settings",
            command=self.save_settings
        )
        save_btn.pack(pady=20)
        
    def create_about_interface(self):
        """Create about interface"""
        scroll_frame = ctk.CTkScrollableFrame(self.main_content)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(scroll_frame, text="About AI Vulnerability Scanner", font=("Arial", 24, "bold")).pack(anchor="w", pady=(0, 20))
        
        info_text = """AI-Powered Vulnerability Scanner v1.0

A comprehensive tool that uses machine learning to predict vulnerabilities based on Nmap, Gobuster, and Nikto scan results.

Core Features:
• Nmap integration for port and service scanning
• Gobuster for directory and file discovery
• Nikto for web vulnerability scanning
• AI model for vulnerability prediction and CVSS scoring
• PDF report generation
• Dark theme optimized for security professionals

This tool is designed for educational and professional security assessment purposes."""
        ctk.CTkLabel(scroll_frame, text=info_text, justify="left").pack(anchor="w", pady=10)
        
    def save_settings(self):
        """Save scanner settings"""
        messagebox.showinfo("Settings", "Scanner settings saved successfully!")
            
    def run(self):
        """Start the application"""
        self.window.mainloop()

if __name__ == "__main__":
    # Check if customtkinter is installed
    try:
        import customtkinter
    except ImportError:
        print("CustomTkinter is required. Install it with:")
        print("pip install customtkinter")
        exit(1)
        
    app = AIVulnerabilityScanner()
    app.run()
