import json

class ThreatDetector:
    """Detects security threats in log messages using Trie & HashMap."""

    def __init__(self, threat_file="threat_patterns.json"):
        """
        Initializes the ThreatDetector with predefined threat patterns.
        
        :param threat_file: JSON file containing known attack patterns
        """
        self.threat_patterns = {}  # HashMap of known attack patterns
        self.threat_trie = {}  # Trie structure for fast lookup
        self.load_threat_patterns(threat_file)

    def add_threat_pattern(self, pattern):
        """
        Adds a threat pattern to both the Trie and HashMap for fast detection.
        
        :param pattern: Suspicious keyword or phrase (e.g., "SQL Injection")
        """
        pattern = pattern.lower()
        node = self.threat_trie
        for char in pattern:
            if char not in node:
                node[char] = {}
            node = node[char]
        node["end"] = True
        self.threat_patterns[pattern] = True  # Add to HashMap

    def load_threat_patterns(self, threat_file):
        """
        Loads threat patterns from a JSON file.
        
        :param threat_file: JSON file containing a list of attack patterns
        """
        try:
            with open(threat_file, "r", encoding="utf-8") as file:
                patterns = json.load(file)
                for pattern in patterns:
                    self.add_threat_pattern(pattern)
        except FileNotFoundError:
            print(f"Warning: Threat patterns file '{threat_file}' not found. Using default patterns.")
            default_patterns = [
                "sql injection", "unauthorized access", "brute force attack",
                "ddos attack", "malware detected", "data breach"
            ]
            for pattern in default_patterns:
                self.add_threat_pattern(pattern)

    def detect_threat(self, log_message):
        """
        Checks if a log message contains a known threat pattern.
        
        :param log_message: Log message string to scan
        :return: Boolean (True if threat detected, False otherwise)
        """
        log_message = log_message.lower()
        node = self.threat_trie

        for char in log_message:
            if char in node:
                node = node[char]
                if "end" in node:  # Match found in Trie
                    return True
            else:
                node = self.threat_trie  # Reset search

        return any(pattern in log_message for pattern in self.threat_patterns)  # HashMap search


# Run a test when executing this file directly
if __name__ == "__main__":
    detector = ThreatDetector()

    # Test log messages
    test_logs = [
        "User attempted SQL Injection",
        "System running smoothly",
        "Multiple failed logins detected, possible brute force attack",
        "Unauthorized access detected in server logs"
    ]

    print("\nThreat Detection Results:")
    for log in test_logs:
        result = detector.detect_threat(log)
        print(f"{log} --> {'🚨 Threat Detected' if result else '✅ Safe'}")
