import numpy as np
import math

class AnomalyDetector:
    def __init__(self):
        self.history = []
        
    def calculate_entropy(self, text):
        # Calculates Shannon entropy of the text
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def is_anomalous(self, message):
        # Checks if a message is suspicious using multiple detection methods
        suspicious_keywords = ["DROP TABLE", "SELECT *", "<script>", "alert("]
        for kw in suspicious_keywords:
            if kw.lower() in message.lower():
                return True, "Suspicious Keyword Detected"

        if self.calculate_entropy(message) > 5.0:
             return True, "High Entropy (Potential Injection)"

        msg_len = len(message)
        self.history.append(msg_len)
        if len(self.history) > 5:
            mean = np.mean(self.history)
            std = np.std(self.history)
            if std > 0:
                z_score = (msg_len - mean) / std
                if abs(z_score) > 3:
                    return True, "Length Outlier (Z-Score > 3)"
        
        return False, "Safe"