import tkinter as tk
from tkinter import messagebox, ttk
import threading
from src.detector import detect_phishing

class PhishingDetectionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishingDetection v1.0 - Live Real-Time Detector")
        self.root.geometry("600x550")
        self.root.configure(bg="#f0f2f5")

        # Header
        tk.Label(root, text="PhishingDetection Live Scanner", font=("Arial", 22, "bold"), bg="#f0f2f5", fg="#1a73e8").pack(pady=15)

        # Input Area
        self.url_entry = tk.Entry(root, font=("Arial", 14), width=45, bd=0, highlightthickness=1)
        self.url_entry.pack(pady=10, padx=20)
        self.url_entry.insert(0, "https://")

        # Progress Bar (Hidden by default)
        self.progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="indeterminate")
        
        # Scan Button
        self.scan_btn = tk.Button(root, text="START LIVE SCAN", command=self.start_scan_thread, 
                                  font=("Arial", 12, "bold"), bg="#1a73e8", fg="white", 
                                  padx=20, pady=10, relief="flat", cursor="hand2")
        self.scan_btn.pack(pady=15)

        # Result Display Area
        self.result_frame = tk.Frame(root, bg="white", bd=1, relief="solid")
        self.result_frame.pack(pady=10, padx=20, fill="both", expand=True)

        self.verdict_label = tk.Label(self.result_frame, text="System Ready", font=("Arial", 14, "bold"), bg="white")
        self.verdict_label.pack(pady=10)

        self.details_text = tk.Text(self.result_frame, font=("Consolas", 10), height=10, bg="white", bd=0)
        self.details_text.pack(pady=5, padx=10)

    def start_scan_thread(self):
        url = self.url_entry.get().strip()
    
        # Fix double https:// or missing protocol
        if url.startswith("https://https://"):
            url = url.replace("https://https://", "https://")
        elif not url.startswith("http"):
            url = "https://" + url

        # UI Updates before scan
        self.scan_btn.config(state="disabled", text="SCANNING...")
        self.progress.pack(pady=5)
        self.progress.start(10)
        self.verdict_label.config(text="Requesting Live API Analysis...", fg="orange")
        
        # Launch Thread
        thread = threading.Thread(target=self.run_logic, args=(url,))
        thread.start()

    def run_logic(self, url):
        try:
            # This calls your src/detector.py which now has the 'Forced Rescan'
            verdict, details = detect_phishing(url)
            
            # Update UI from the thread safely
            self.root.after(0, self.update_ui, verdict, details)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {e}"))
            self.root.after(0, self.reset_ui)

    def update_ui(self, verdict, details):
        self.progress.stop()
        self.progress.pack_forget()
        self.scan_btn.config(state="normal", text="START LIVE SCAN")

        # Color coding
        color = "#28a745" if "SAFE" in verdict else "#dc3545" if "PHISHING" in verdict else "#ffc107"
        self.verdict_label.config(text=f"VERDICT: {verdict}", fg=color)

        # Show details
        self.details_text.delete('1.0', tk.END)
        self.details_text.insert(tk.END, f"{'ENGINE/FEATURE':<25} | {'RESULT'}\n")
        self.details_text.insert(tk.END, "-"*45 + "\n")
        for feat, val in details.items():
            status = "[!] DETECTED" if val == 1 else "[OK] CLEAN"
            self.details_text.insert(tk.END, f"{feat.replace('_', ' ').title():<25} | {status}\n")

    def reset_ui(self):
        self.progress.stop()
        self.progress.pack_forget()
        self.scan_btn.config(state="normal", text="START LIVE SCAN")

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetectionGUI(root)
    root.mainloop()