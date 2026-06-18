import re
from .ast_analyzer import ASTAnalyzer

class XSSDetector:
    def __init__(self, rules: list):
        self.compiled_rules = []
        for rule in rules:
            self.compiled_rules.append({
                "id": rule["id"],
                "name": rule["name"],
                "pattern": re.compile(rule["regex"]),
                "score": rule["risk_score"]
            })
        self.ast_analyzer = ASTAnalyzer()

    def analyze(self, normalized_variations: dict, threshold: int = 100) -> dict:
        total_score = 0
        triggered_rules = []

        # We test the rules against the 'combined_fully_decoded' string 
        # to catch payloads that use mixed encoding.
        target_string = normalized_variations["combined_fully_decoded"]

        # 1. Regex Engine Analysis
        for rule in self.compiled_rules:
            if rule["pattern"].search(target_string):
                total_score += rule["score"]
                triggered_rules.append(rule["name"])

        # 2. AST Engine Analysis
        ast_result = self.ast_analyzer.analyze(target_string)
        total_score += ast_result["score"]
        triggered_rules.extend(ast_result["triggered_rules"])

        return {
            "is_malicious": total_score >= threshold,
            "score": total_score,
            "triggered_rules": triggered_rules
        }
