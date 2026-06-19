from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import List, Tuple, Dict

class Mutator:
    """
    Handles URL parsing and the injection of payloads into URL parameters.
    
    Security Context:
    This module must ensure that when injecting into a parameter, the REST of the 
    parameters remain untouched. Modifying multiple parameters simultaneously can 
    break the application logic in ways unrelated to SQLi, causing false negatives.
    """

    def __init__(self, target_url: str):
        self.original_url = target_url
        self.parsed_url = urlparse(target_url)
        # parse_qsl keeps parameters as a list of tuples to maintain order and handle duplicates
        self.parameters: List[Tuple[str, str]] = parse_qsl(self.parsed_url.query, keep_blank_values=True)

    def get_mutated_urls(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generates a list of URLs, each having ONE parameter replaced with the payload.
        
        Returns:
            List of Tuples: [(parameter_name, mutated_url), ...]
        """
        mutated_urls = []
        
        # If no parameters, return empty (nothing to inject into)
        if not self.parameters:
            return mutated_urls

        for i, (param_name, param_value) in enumerate(self.parameters):
            # Create a copy of the parameters
            mutated_params = self.parameters.copy()
            
            # Inject the payload by appending it to the original value
            # Appending (e.g., id=1') is generally more effective than replacing (e.g., id=')
            # because the application might have type checking (e.g., "id must start with a number")
            mutated_params[i] = (param_name, param_value + payload)
            
            # Reconstruct the query string
            new_query = urlencode(mutated_params)
            
            # Reconstruct the full URL
            new_url_parts = list(self.parsed_url)
            new_url_parts[4] = new_query # index 4 is the query string
            new_url = urlunparse(new_url_parts)
            
            mutated_urls.append((param_name, new_url))
            
        return mutated_urls
