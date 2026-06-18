from html.parser import HTMLParser

class ASTAnalyzer(HTMLParser):
    def __init__(self):
        super().__init__()
        self.score = 0
        self.triggered_rules = []

    def handle_starttag(self, tag, attrs):
        # 1. Catch script tags directly
        if tag.lower() == 'script':
            self.score += 100
            self.triggered_rules.append("AST: Structural Script Tag")

        # 2. Check all attributes for event handlers or JS protocol
        for attr, val in attrs:
            attr_lower = attr.lower()
            if attr_lower.startswith('on'):
                self.score += 80
                self.triggered_rules.append(f"AST: Structural Event Handler ({attr})")
            
            if attr_lower in ('href', 'src') and val:
                # Strip whitespaces and check for javascript: protocol
                if val.strip().lower().startswith('javascript:'):
                    self.score += 90
                    self.triggered_rules.append(f"AST: JavaScript URI in {attr} attribute")

    def analyze(self, html_content: str) -> dict:
        self.score = 0
        self.triggered_rules = []
        
        try:
            self.feed(html_content)
        except Exception:
            # If the HTML is so malformed the parser breaks, we gracefully ignore
            # but in a real WAF we might flag this as highly suspicious
            pass
            
        return {
            "score": self.score,
            "triggered_rules": self.triggered_rules
        }
