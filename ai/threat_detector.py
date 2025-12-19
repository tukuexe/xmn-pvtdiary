#!/usr/bin/env python3
"""
Advanced AI Threat Detection System
Uses machine learning to detect security threats in real-time
"""

import numpy as np
import tensorflow as tf
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import pickle
import hashlib
import json

@dataclass
class ThreatVector:
    """Represents a security threat vector"""
    ip_address: str
    user_agent: str
    location: Tuple[float, float]
    request_frequency: float
    failed_attempts: int
    access_pattern: str
    timestamp: datetime
    device_fingerprint: str
    behavioral_signature: List[float]

class NeuralThreatDetector:
    """Deep learning based threat detection system"""
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.threshold = 0.85
        self.threat_database = {}
        self.initialize_model(model_path)
        
    def initialize_model(self, model_path: str = None):
        """Initialize or load the neural network model"""
        if model_path and os.path.exists(model_path):
            self.model = tf.keras.models.load_model(model_path)
        else:
            self.model = self.build_model()
            
    def build_model(self) -> tf.keras.Model:
        """Build a convolutional neural network for threat detection"""
        model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(128, 1)),
            tf.keras.layers.Conv1D(64, 3, activation='relu', padding='same'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.MaxPooling1D(2),
            tf.keras.layers.Conv1D(128, 3, activation='relu', padding='same'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.MaxPooling1D(2),
            tf.keras.layers.Conv1D(256, 3, activation='relu', padding='same'),
            tf.keras.layers.GlobalAveragePooling1D(),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
        )
        
        return model
    
    def extract_features(self, threat_vector: ThreatVector) -> np.ndarray:
        """Extract features from threat vector for neural network"""
        features = []
        
        # IP address features (hashed)
        ip_hash = int(hashlib.md5(threat_vector.ip_address.encode()).hexdigest()[:8], 16)
        features.append(ip_hash % 1000 / 1000.0)
        
        # User agent complexity
        ua_length = len(threat_vector.user_agent)
        features.append(min(ua_length / 500.0, 1.0))
        
        # Geographic features
        lat, lon = threat_vector.location
        features.append(abs(lat) / 90.0)
        features.append(abs(lon) / 180.0)
        
        # Behavioral features
        features.append(min(threat_vector.request_frequency / 100.0, 1.0))
        features.append(min(threat_vector.failed_attempts / 10.0, 1.0))
        
        # Access pattern analysis
        pattern_score = self.analyze_access_pattern(threat_vector.access_pattern)
        features.append(pattern_score)
        
        # Device fingerprint entropy
        fingerprint_entropy = self.calculate_entropy(threat_vector.device_fingerprint)
        features.append(fingerprint_entropy)
        
        # Time-based features
        hour = threat_vector.timestamp.hour
        features.append(hour / 24.0)
        
        # Add behavioral signature if available
        if threat_vector.behavioral_signature:
            features.extend(threat_vector.behavioral_signature[:20])  # Use first 20 features
        
        # Pad or truncate to 128 features
        if len(features) < 128:
            features.extend([0.0] * (128 - len(features)))
        else:
            features = features[:128]
        
        return np.array(features).reshape(1, 128, 1)
    
    def analyze_access_pattern(self, pattern: str) -> float:
        """Analyze access pattern for anomalies"""
        if not pattern:
            return 0.5
        
        # Calculate pattern randomness
        char_freq = {}
        for char in pattern:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        entropy = 0.0
        total_chars = len(pattern)
        for count in char_freq.values():
            probability = count / total_chars
            entropy -= probability * np.log2(probability)
        
        # Normalize entropy to 0-1 range
        max_entropy = np.log2(len(char_freq)) if char_freq else 0
        return entropy / max_entropy if max_entropy > 0 else 0.5
    
    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = data.count(chr(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * np.log2(p_x)
        
        return entropy / 8.0  # Normalize to 0-1
    
    def predict_threat_level(self, threat_vector: ThreatVector) -> Tuple[float, str]:
        """Predict threat level using neural network"""
        features = self.extract_features(threat_vector)
        
        # Get neural network prediction
        prediction = self.model.predict(features, verbose=0)[0][0]
        
        # Determine threat category
        if prediction >= 0.9:
            category = "CRITICAL"
        elif prediction >= 0.7:
            category = "HIGH"
        elif prediction >= 0.5:
            category = "MEDIUM"
        elif prediction >= 0.3:
            category = "LOW"
        else:
            category = "SAFE"
        
        return float(prediction), category
    
    def train_model(self, training_data: List[Tuple[ThreatVector, int]], epochs: int = 50):
        """Train the neural network with labeled data"""
        X_train = []
        y_train = []
        
        for threat_vector, label in training_data:
            features = self.extract_features(threat_vector)
            X_train.append(features.squeeze())
            y_train.append(label)
        
        X_train = np.array(X_train).reshape(-1, 128, 1)
        y_train = np.array(y_train)
        
        # Train the model
        history = self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=32,
            validation_split=0.2,
            verbose=1
        )
        
        return history
    
    def update_threat_database(self, ip: str, threat_level: float):
        """Update threat intelligence database"""
        if ip not in self.threat_database:
            self.threat_database[ip] = {
                'first_seen': datetime.now(),
                'threat_history': [],
                'total_score': 0.0
            }
        
        self.threat_database[ip]['threat_history'].append({
            'timestamp': datetime.now(),
            'threat_level': threat_level
        })
        
        # Update total score (weighted average)
        history = self.threat_database[ip]['threat_history']
        recent_weight = 1.5
        total = sum(h['threat_level'] * (recent_weight if i == len(history)-1 else 1.0) 
                   for i, h in enumerate(history))
        count = sum(recent_weight if i == len(history)-1 else 1.0 for i in range(len(history)))
        
        self.threat_database[ip]['total_score'] = total / count
        
        # Prune old entries
        if len(history) > 100:
            self.threat_database[ip]['threat_history'] = history[-50:]
    
    def get_global_threat_analysis(self) -> Dict:
        """Generate global threat analysis report"""
        total_ips = len(self.threat_database)
        high_threat = sum(1 for ip_data in self.threat_database.values() 
                         if ip_data['total_score'] > 0.7)
        
        recent_threats = []
        for ip, data in list(self.threat_database.items())[-10:]:
            if data['threat_history']:
                recent_threats.append({
                    'ip': ip,
                    'latest_threat': data['threat_history'][-1]['threat_level'],
                    'first_seen': data['first_seen'].isoformat()
                })
        
        return {
            'total_monitored_ips': total_ips,
            'high_threat_ips': high_threat,
            'threat_percentage': (high_threat / total_ips * 100) if total_ips > 0 else 0,
            'recent_threats': recent_threats,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def save_model(self, path: str):
        """Save the trained model"""
        self.model.save(path)
        # Also save threat database
        with open(path.replace('.h5', '_database.pkl'), 'wb') as f:
            pickle.dump(self.threat_database, f)
    
    def load_model(self, path: str):
        """Load a trained model"""
        self.model = tf.keras.models.load_model(path)
        # Load threat database if exists
        db_path = path.replace('.h5', '_database.pkl')
        if os.path.exists(db_path):
            with open(db_path, 'rb') as f:
                self.threat_database = pickle.load(f)

# Real-time threat monitoring system
class RealTimeThreatMonitor:
    """Monitors threats in real-time with streaming analysis"""
    
    def __init__(self, detector: NeuralThreatDetector):
        self.detector = detector
        self.threat_stream = []
        self.alert_threshold = 0.8
        self.alerts_enabled = True
        
    def process_event(self, event_data: Dict) -> Optional[Dict]:
        """Process a security event in real-time"""
        # Convert event to threat vector
        threat_vector = ThreatVector(
            ip_address=event_data.get('ip', '0.0.0.0'),
            user_agent=event_data.get('user_agent', ''),
            location=event_data.get('location', (0.0, 0.0)),
            request_frequency=event_data.get('request_freq', 0.0),
            failed_attempts=event_data.get('failed_attempts', 0),
            access_pattern=event_data.get('access_pattern', ''),
            timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat())),
            device_fingerprint=event_data.get('device_fingerprint', ''),
            behavioral_signature=event_data.get('behavioral_signature', [])
        )
        
        # Get threat prediction
        threat_level, category = self.detector.predict_threat_level(threat_vector)
        
        # Update threat database
        self.detector.update_threat_database(threat_vector.ip_address, threat_level)
        
        # Store in stream
        event_result = {
            'timestamp': datetime.now().isoformat(),
            'ip': threat_vector.ip_address,
            'threat_level': threat_level,
            'category': category,
            'recommended_action': self.get_recommended_action(threat_level)
        }
        
        self.threat_stream.append(event_result)
        
        # Trigger alert if needed
        if threat_level >= self.alert_threshold and self.alerts_enabled:
            self.trigger_alert(event_result)
        
        return event_result
    
    def get_recommended_action(self, threat_level: float) -> str:
        """Get recommended security action based on threat level"""
        if threat_level >= 0.9:
            return "IMMEDIATE_LOCKDOWN"
        elif threat_level >= 0.7:
            return "BLOCK_IP_AND_NOTIFY"
        elif threat_level >= 0.5:
            return "REQUIRE_ADDITIONAL_AUTH"
        elif threat_level >= 0.3:
            return "MONITOR_CLOSELY"
        else:
            return "ALLOW"
    
    def trigger_alert(self, event_result: Dict):
        """Trigger security alert"""
        alert_message = (
            f"🚨 SECURITY ALERT 🚨\n"
            f"Threat Level: {event_result['category']} ({event_result['threat_level']:.2%})\n"
            f"IP Address: {event_result['ip']}\n"
            f"Time: {event_result['timestamp']}\n"
            f"Action: {event_result['recommended_action']}"
        )
        
        # In production, this would send to Telegram/Slack/etc.
        print(alert_message)
        
    def get_stream_analysis(self, window_minutes: int = 5) -> Dict:
        """Get analysis of recent threat stream"""
        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        recent_events = [e for e in self.threat_stream 
                        if datetime.fromisoformat(e['timestamp']) > cutoff]
        
        if not recent_events:
            return {'event_count': 0, 'average_threat': 0.0}
        
        avg_threat = sum(e['threat_level'] for e in recent_events) / len(recent_events)
        high_threats = sum(1 for e in recent_events if e['threat_level'] > 0.7)
        
        return {
            'event_count': len(recent_events),
            'average_threat': avg_threat,
            'high_threat_count': high_threats,
            'threat_trend': 'INCREASING' if len(recent_events) > 10 else 'STABLE'
      }
