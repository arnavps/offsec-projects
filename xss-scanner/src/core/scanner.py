import requests

class Scanner:
    def __init__(self, crawler):
        self.crawler = crawler

    def scan_page(self, url: str, payloads: list) -> bool:
        """
        Scans a single page by extracting its forms and injecting payloads.
        Returns True if a vulnerability is found.
        """
        print(f"[*] Crawling {url} for forms...")
        forms = self.crawler.extract_forms(url)
        print(f"[+] Found {len(forms)} forms on {url}.")
        
        is_vulnerable = False

        for form in forms:
            form_details = self.crawler.parse_form_details(form, url)
            
            for payload in payloads:
                # We strip newlines from the payload text file
                payload = payload.strip()
                if not payload:
                    continue
                    
                response = self.submit_form(form_details, url, payload)
                
                # The ultimate check: Did the server reflect our payload unsanitized?
                if response and payload in response.text:
                    print(f"\n[!!!] XSS VULNERABILITY FOUND [!!!]")
                    print(f"[*] URL: {url}")
                    print(f"[*] Form Action: {form_details['action']}")
                    print(f"[*] Payload: {payload}\n")
                    is_vulnerable = True
                    # In a real scanner, you might break here or continue to find more
                    break 

        return is_vulnerable

    def submit_form(self, form_details: dict, url: str, payload: str):
        """
        Replaces input fields with our payload and submits the request.
        """
        target_url = form_details["action"]
        method = form_details["method"]
        inputs = form_details["inputs"]

        data = {}
        for input_field in inputs:
            # We inject the payload into text and search fields. 
            # We leave hidden fields alone or just send their default value.
            if input_field["type"] in ["text", "search"]:
                data[input_field["name"]] = payload
            else:
                data[input_field["name"]] = input_field["value"]

        try:
            if method == "post":
                return self.crawler.session.post(target_url, data=data, timeout=5)
            else:
                # GET requests put data in the URL query parameters
                return self.crawler.session.get(target_url, params=data, timeout=5)
        except Exception as e:
            # print(f"[-] Request failed: {e}")
            return None
