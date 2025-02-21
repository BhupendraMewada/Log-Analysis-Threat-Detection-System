import joblib
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

class AnomalyDetector:
    """Detects anomalies in log messages using Machine Learning (TF-IDF + Random Forest)."""
    
    MODEL_PATH = "models/anomaly_model.pkl"

    def __init__(self):
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")  # Use bigrams and remove stopwords
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)  # Random Forest with 100 trees
        self._load_or_train_model()
    
    def _load_or_train_model(self):
        """Loads the trained model if available; otherwise, initializes an empty model."""
        if os.path.exists(self.MODEL_PATH):
            self.vectorizer, self.model = joblib.load(self.MODEL_PATH)
            print("✅ Pre-trained model loaded.")
        else:
            print("⚠️ Warning: No trained model found. Train the model first.")

    def train_model(self, log_messages, labels):
        """Trains the anomaly detection model using log messages."""
        if not log_messages or not labels:
            print("❌ Error: No log messages or labels provided for training.")
            return
        
        X = self.vectorizer.fit_transform(log_messages)
        self.model.fit(X.toarray(), labels)
        joblib.dump((self.vectorizer, self.model), self.MODEL_PATH)
        print("✅ Anomaly detection model trained and saved.")

    def detect_anomaly(self, log_message):
        """Predicts whether a given log message is an anomaly."""
        if not log_message or not os.path.exists(self.MODEL_PATH):
            return False
        
        X = self.vectorizer.transform([log_message])  # Use trained vectorizer
        prediction = self.model.predict(X.toarray())
        return prediction[0] == -1  # -1 means anomaly, 1 means normal


# Run a test when executing this file directly
if __name__ == "__main__":
    detector = AnomalyDetector()
    
    # Training logs with labels (1 = normal, -1 = anomaly)
    training_logs = [
        # Normal logs
        "User logged in successfully", "File accessed by user", "System rebooted", "User updated profile",
        "Normal database query executed", "Email sent to customer", "Firewall rule updated",
        "Backup completed successfully", "Server disk space low", "Network latency detected",
        "User logged out", "File deleted by user", "System shutdown", "User password changed",
        "Database backup started", "Email received from customer", "Firewall rule deleted",
        "Server disk space critical", "Network packet loss detected", "User session expired",
        
        # Anomalous logs
        "Multiple failed login attempts", "Unauthorized access detected", "DDoS attack detected",
        "SQL Injection attack detected", "Malware found in system", "User privilege escalation attempt detected",
        "Suspicious activity from unknown IP", "Brute force attack detected", "Phishing attempt blocked",
        "Ransomware activity detected", "Unauthorized file access detected", "DDoS attack mitigated",
        "SQL Injection attempt blocked", "Malware quarantined", "User privilege escalation failed",
        "Suspicious activity from known IP", "Brute force attack blocked", "Phishing email reported",
        "Ransomware detected and removed", "Unauthorized file modification detected", "Suspicious process running"
    ]
    labels = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]
    
    # Ensure the lengths of training_logs and labels match
    if len(training_logs) != len(labels):
        print(f"❌ Error: Length mismatch! training_logs has {len(training_logs)} items, but labels has {len(labels)} items.")
    else:
        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(training_logs, labels, test_size=0.3, random_state=42)
        
        # Train the model
        detector.train_model(X_train, y_train)
        
        # Evaluate the model
        y_pred = [detector.detect_anomaly(log) for log in X_test]
        y_pred = [-1 if pred else 1 for pred in y_pred]  # Convert to -1/1 format
        
        print("\n📊 Model Evaluation:")
        print(classification_report(y_test, y_pred, target_names=["Normal", "Anomaly"], zero_division=0))
        
        # Test anomaly detection
        test_logs = [
            "User attempted SQL Injection", "Normal user activity detected", "High number of failed login attempts",
            "DDoS attack detected", "Unauthorized file modification detected", "Suspicious process running on the server"
        ]
        
        print("\n🔍 Anomaly Detection Results:")
        for log in test_logs:
            result = detector.detect_anomaly(log)
            print(f"{log} --> {'🚨 Anomaly Detected' if result else '✅ Normal'}")