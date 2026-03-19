import sys
import os

# This line tells Python to look in the current folder for the 'src' module
sys.path.append(os.getcwd())

from src.detector import detect_phishing

def main():
    print("\n" + "="*40)
    print("   RULE-BASED PHISHING DETECTOR v1.0")
    print("="*40)
    
    url = input("\nEnter URL to scan (or 'exit' to quit): ").strip()
    
    if url.lower() == 'exit':
        return

    if not url:
        print("Error: URL cannot be empty!")
        return
        
    if not url.startswith('http'):
        url = 'http://' + url
        
    print(f"\n[+] Analyzing: {url}...")
    
    try:
        verdict, details = detect_phishing(url)
        
        print(f"\nFINAL VERDICT: {verdict}")
        print("-" * 40)
        print(f"{'FEATURE':<25} | {'STATUS'}")
        print("-" * 40)
        
        for feature, value in details.items():
            feature_name = feature.replace('_', ' ').title()
            status = "[!] FLAGED" if value == 1 else "[OK] CLEAN"
            print(f"{feature_name:<25} | {status}")
            
    except Exception as e:
        print(f"\n[!] An error occurred during detection: {e}")

    print("\n" + "="*40)
    input("Press Enter to close...") # Keeps the terminal window open

if __name__ == "__main__":
    main()