import re
import os
from datetime import datetime
from threat_detector import ThreatDetector
from anomaly_detector import AnomalyDetector

class LogEntry:
    """Represents a structured log entry."""
    
    def __init__(self, timestamp, level, source, message):
        self.timestamp = timestamp
        self.level = level
        self.source = source
        self.message = message

    def __repr__(self):
        return f"[{self.timestamp}] {self.level} - {self.source}: {self.message}"


class LogParser:
    """Parses log files and checks for security threats & anomalies."""
    
    LOG_PATTERN = re.compile(r"\[(.*?)\] (\w+) - (.+): (.+)")

    def __init__(self, log_file):
        self.log_file = log_file
        self.threat_detector = ThreatDetector()
        self.anomaly_detector = AnomalyDetector()

    def parse_log(self, log_line):
        """Parses a single log entry into a structured object."""
        match = self.LOG_PATTERN.match(log_line)
        if match:
            try:
                timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                return LogEntry(timestamp, match.group(2), match.group(3), match.group(4))
            except ValueError as e:
                print(f"Error parsing timestamp: {e}")
        return None

    def analyze_log(self, log_entry):
        """Checks if a log entry is a threat or an anomaly."""
        is_threat = self.threat_detector.detect_threat(log_entry.message)
        is_anomaly = self.anomaly_detector.detect_anomaly(log_entry.message)
        return is_threat, is_anomaly

    def read_logs(self):
        """Reads and analyzes all logs from a file."""
        logs = []
        if not os.path.exists(self.log_file):
            print(f"Error: Log file '{self.log_file}' not found.")
            return logs

        try:
            with open(self.log_file, "r", encoding="utf-8") as file:
                for line in file:
                    log_entry = self.parse_log(line.strip())
                    if log_entry:
                        logs.append(log_entry)
        except Exception as e:
            print(f"Error reading log file: {e}")

        return logs


# Run when executing this file directly
if __name__ == "__main__":
    parser = LogParser("logs/sample.log")
    parsed_logs = parser.read_logs()

    print("\n🔍 Log Analysis Results:")
    for log in parsed_logs:
        is_threat, is_anomaly = parser.analyze_log(log)
        status = "✅ Safe"
        if is_threat:
            status = "🚨 Threat Detected"
        elif is_anomaly:
            status = "⚠️ Anomaly Detected"
        print(f"{log} --> {status}")
