import urllib.parse
import html

class InputNormalizer:
    def __init__(self):
        pass

    def normalize(self, raw_input: str) -> dict:
        """
        Takes raw input and returns a dictionary of variations.
        A real engine tests the signature against multiple forms of the string.
        """
        variations = {
            "raw": raw_input,
            "url_decoded": self._url_decode_deep(raw_input),
            "html_decoded": self._html_decode_deep(raw_input),
        }
        
        # The 'ultimate' decoded version combining both
        combined = self._html_decode_deep(variations["url_decoded"])
        variations["combined_fully_decoded"] = combined.lower()
        
        return variations

    def _url_decode_deep(self, text: str, max_depth: int = 3) -> str:
        # Prevent infinite loops on recursive encoding
        current = text
        for _ in range(max_depth):
            decoded = urllib.parse.unquote_plus(current)
            if decoded == current:
                break
            current = decoded
        return current

    def _html_decode_deep(self, text: str, max_depth: int = 3) -> str:
        current = text
        for _ in range(max_depth):
            decoded = html.unescape(current)
            if decoded == current:
                break
            current = decoded
        return current
