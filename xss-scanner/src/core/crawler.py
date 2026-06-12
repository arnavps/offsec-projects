import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class Crawler:
    def __init__(self):
        # We use a session so we can maintain cookies if needed
        self.session = requests.Session()
        # Add a user agent so servers don't immediately block us
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Vanguard Scanner"
        })

    def extract_forms(self, url: str) -> list:
        """
        Fetches the HTML of the URL and extracts all <form> tags.
        """
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"[-] Crawler Error: Could not connect to {url} - {str(e)}")
            return []

    def parse_form_details(self, form, url: str) -> dict:
        """
        Extracts the action (endpoint), method (GET/POST), and all input fields from a form.
        """
        details = {}
        
        # Get the action URL (where the data is sent)
        action = form.attrs.get("action")
        if action:
            # Resolves relative URLs (e.g., /search.php) into absolute URLs
            action = urljoin(url, action)
        else:
            action = url
            
        details["action"] = action
        
        # Get the HTTP method, default to GET
        method = form.attrs.get("method", "get").lower()
        details["method"] = method
        
        # Get all input fields
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            
            # We only care about fields with a name attribute
            if input_name:
                inputs.append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_value
                })
                
        details["inputs"] = inputs
        return details
