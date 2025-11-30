import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input
from tensorflow.keras.optimizers import Adam
import joblib
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import redis
import requests

# Configure structured logging
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from logging_config import setup_logging, log_info, log_error, log_warning
    logger = setup_logging(
        service_name="behavioral_analysis",
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        environment=os.getenv('ENVIRONMENT', 'development'),
        log_file=os.getenv('LOG_FILE', '/app/logs/behavioral_analysis.log')
    )
except ImportError:
    # Fallback to basic logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

class BehavioralAnalysisEngine:
    """Behavioral Analysis Engine with LSTM, Isolation Forest, and Autoencoder models"""
    
    def __init__(self, model_path: str = "/app/models", redis_url: str = "redis://redis:6379"):
        self.model_path = model_path
        self.redis_client = redis.from_url(redis_url)
        self.scaler = StandardScaler()
        
        # Integration with adaptive deception
        self.adaptive_deception_url = "http://adaptive_deception:5007"
        
        # Initialize models
        self.lstm_model = None
        self.isolation_forest = None
        self.autoencoder = None
        
        # Load or create models
        self._load_models()
    
    def _load_models(self):
        """Load existing models or create new ones"""
        try:
            # Load LSTM model
            if os.path.exists(f"{self.model_path}/lstm_model.h5"):
                self.lstm_model = tf.keras.models.load_model(f"{self.model_path}/lstm_model.h5")
                logger.info("LSTM model loaded successfully")
            else:
                self._create_lstm_model()
            
            # Load Isolation Forest
            if os.path.exists(f"{self.model_path}/isolation_forest.pkl"):
                self.isolation_forest = joblib.load(f"{self.model_path}/isolation_forest.pkl")
                logger.info("Isolation Forest model loaded successfully")
            else:
                self._create_isolation_forest()
            
            # Load Autoencoder
            if os.path.exists(f"{self.model_path}/autoencoder.h5"):
                self.autoencoder = tf.keras.models.load_model(f"{self.model_path}/autoencoder.h5")
                logger.info("Autoencoder model loaded successfully")
            else:
                self._create_autoencoder()
                
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            self._create_all_models()
    
    def _create_lstm_model(self):
        """Create LSTM model for sequence-based anomaly detection"""
        try:
            self.lstm_model = Sequential([
                LSTM(64, return_sequences=True, input_shape=(None, 10)),
                Dropout(0.2),
                LSTM(32, return_sequences=False),
                Dropout(0.2),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            self.lstm_model.compile(
                optimizer=Adam(learning_rate=0.001),
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            # Save model
            os.makedirs(self.model_path, exist_ok=True)
            self.lstm_model.save(f"{self.model_path}/lstm_model.h5")
            logger.info("LSTM model created and saved")
            
        except Exception as e:
            logger.error(f"Error creating LSTM model: {e}")
    
    def _create_isolation_forest(self):
        """Create Isolation Forest model for unsupervised anomaly detection"""
        try:
            self.isolation_forest = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            
            # Save model
            os.makedirs(self.model_path, exist_ok=True)
            joblib.dump(self.isolation_forest, f"{self.model_path}/isolation_forest.pkl")
            logger.info("Isolation Forest model created and saved")
            
        except Exception as e:
            logger.error(f"Error creating Isolation Forest model: {e}")
    
    def _create_autoencoder(self):
        """Create Autoencoder model for dimensionality reduction and anomaly detection"""
        try:
            # Encoder
            input_layer = Input(shape=(10,))
            encoded = Dense(8, activation='relu')(input_layer)
            encoded = Dense(4, activation='relu')(encoded)
            
            # Decoder
            decoded = Dense(8, activation='relu')(encoded)
            decoded = Dense(10, activation='sigmoid')(decoded)
            
            self.autoencoder = Model(input_layer, decoded)
            self.autoencoder.compile(optimizer='adam', loss='mse')
            
            # Save model
            os.makedirs(self.model_path, exist_ok=True)
            self.autoencoder.save(f"{self.model_path}/autoencoder.h5")
            logger.info("Autoencoder model created and saved")
            
        except Exception as e:
            logger.error(f"Error creating Autoencoder model: {e}")
    
    def _create_all_models(self):
        """Create all models from scratch"""
        self._create_lstm_model()
        self._create_isolation_forest()
        self._create_autoencoder()
    
    def generate_synthetic_data(self, n_samples: int = 10000) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic network traffic data for training"""
        try:
            # Generate normal traffic patterns
            normal_data = np.random.normal(0, 1, (n_samples, 10))
            
            # Generate some anomalous patterns
            anomaly_indices = np.random.choice(n_samples, size=int(n_samples * 0.1), replace=False)
            normal_data[anomaly_indices] += np.random.normal(3, 2, (len(anomaly_indices), 10))
            
            # Create labels (0 for normal, 1 for anomaly)
            labels = np.zeros(n_samples)
            labels[anomaly_indices] = 1
            
            return normal_data, labels
            
        except Exception as e:
            logger.error(f"Error generating synthetic data: {e}")
            return np.array([]), np.array([])
    
    def train_models(self):
        """Train all models with synthetic data"""
        try:
            logger.info("Generating synthetic training data...")
            X, y = self.generate_synthetic_data()
            
            if len(X) == 0:
                logger.error("Failed to generate training data")
                return False
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train Isolation Forest
            logger.info("Training Isolation Forest...")
            self.isolation_forest.fit(X_train)
            
            # Train Autoencoder
            logger.info("Training Autoencoder...")
            self.autoencoder.fit(
                X_train, X_train,
                epochs=50,
                batch_size=32,
                validation_data=(X_test, X_test),
                verbose=0
            )
            
            # Train LSTM (reshape data for sequence)
            logger.info("Training LSTM...")
            X_lstm = X_train.reshape(-1, 1, 10)
            y_lstm = y_train.reshape(-1, 1)
            
            self.lstm_model.fit(
                X_lstm, y_lstm,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            # Save trained models
            self._save_models()
            
            # Evaluate models
            self._evaluate_models(X_test, y_test)
            
            logger.info("All models trained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
            return False
    
    def _save_models(self):
        """Save all trained models"""
        try:
            os.makedirs(self.model_path, exist_ok=True)
            
            # Save LSTM
            self.lstm_model.save(f"{self.model_path}/lstm_model.h5")
            
            # Save Isolation Forest
            joblib.dump(self.isolation_forest, f"{self.model_path}/isolation_forest.pkl")
            
            # Save Autoencoder
            self.autoencoder.save(f"{self.model_path}/autoencoder.h5")
            
            # Save scaler
            joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
            
            logger.info("All models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def _evaluate_models(self, X_test: np.ndarray, y_test: np.ndarray):
        """Evaluate model performance"""
        try:
            # Isolation Forest predictions
            if_anomalies = self.isolation_forest.predict(X_test)
            if_anomalies = (if_anomalies == -1).astype(int)
            
            # Autoencoder reconstruction error
            reconstructed = self.autoencoder.predict(X_test)
            ae_errors = np.mean(np.square(X_test - reconstructed), axis=1)
            ae_threshold = np.percentile(ae_errors, 90)
            ae_anomalies = (ae_errors > ae_threshold).astype(int)
            
            # LSTM predictions
            X_lstm_test = X_test.reshape(-1, 1, 10)
            lstm_predictions = self.lstm_model.predict(X_lstm_test)
            lstm_anomalies = (lstm_predictions > 0.5).astype(int).flatten()
            
            # Log results
            logger.info("Model Evaluation Results:")
            logger.info(f"Isolation Forest - Anomalies detected: {np.sum(if_anomalies)}")
            logger.info(f"Autoencoder - Anomalies detected: {np.sum(ae_anomalies)}")
            logger.info(f"LSTM - Anomalies detected: {np.sum(lstm_anomalies)}")
            
        except Exception as e:
            logger.error(f"Error evaluating models: {e}")
    
    def _retrain_lstm(self, X_train: np.ndarray, y_train: np.ndarray) -> bool:
        """Retrain LSTM model with new data (Section 6 - Task 24)"""
        try:
            if self.lstm_model is None:
                self._create_lstm_model()
            
            X_lstm = X_train.reshape(-1, 1, 10)
            y_lstm = y_train.reshape(-1, 1)
            
            self.lstm_model.fit(
                X_lstm, y_lstm,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            # Save model
            self.lstm_model.save(f"{self.model_path}/lstm_model.h5")
            logger.info("LSTM model retrained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error retraining LSTM: {e}")
            return False
    
    def _retrain_isolation_forest(self, X_train: np.ndarray, y_train: np.ndarray) -> bool:
        """Retrain Isolation Forest model with new data (Section 6 - Task 24)"""
        try:
            if self.isolation_forest is None:
                self._create_isolation_forest()
            
            self.isolation_forest.fit(X_train)
            
            # Save model
            joblib.dump(self.isolation_forest, f"{self.model_path}/isolation_forest.pkl")
            logger.info("Isolation Forest model retrained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error retraining Isolation Forest: {e}")
            return False
    
    def _retrain_autoencoder(self, X_train: np.ndarray, y_train: np.ndarray) -> bool:
        """Retrain Autoencoder model with new data (Section 6 - Task 24)"""
        try:
            if self.autoencoder is None:
                self._create_autoencoder()
            
            self.autoencoder.fit(
                X_train, X_train,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            # Save model
            self.autoencoder.save(f"{self.model_path}/autoencoder.h5")
            logger.info("Autoencoder model retrained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error retraining Autoencoder: {e}")
            return False
    
    def _evaluate_model_performance(self, model_name: str, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Evaluate a specific model's performance (Section 6 - Task 24)"""
        try:
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
            
            if model_name == 'lstm':
                X_test_reshaped = X_test.reshape(-1, 1, 10)
                predictions = self.lstm_model.predict(X_test_reshaped)
                y_pred = (predictions > 0.5).astype(int).flatten()
            elif model_name == 'isolation_forest':
                predictions = self.isolation_forest.predict(X_test)
                y_pred = (predictions == -1).astype(int)
            elif model_name == 'autoencoder':
                reconstructed = self.autoencoder.predict(X_test)
                errors = np.mean(np.square(X_test - reconstructed), axis=1)
                threshold = np.percentile(errors, 90)
                y_pred = (errors > threshold).astype(int)
            else:
                return {'error': f'Unknown model: {model_name}'}
            
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
            false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            return {
                'accuracy': float(accuracy),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'false_positive_rate': float(false_positive_rate),
                'true_positives': int(tp),
                'true_negatives': int(tn),
                'false_positives': int(fp),
                'false_negatives': int(fn)
            }
            
        except Exception as e:
            logger.error(f"Error evaluating model performance: {e}")
            return {'error': str(e)}
    
    def detect_anomalies(self, data: np.ndarray) -> Dict[str, any]:
        """Detect anomalies using all three models"""
        try:
            if data.shape[1] != 10:
                raise ValueError("Input data must have 10 features")
            
            results = {
                'timestamp': datetime.now().isoformat(),
                'data_points': len(data),
                'anomalies_detected': 0,
                'model_predictions': {},
                'confidence_scores': {},
                'recommendations': []
            }
            
            # Isolation Forest detection
            if self.isolation_forest:
                if_predictions = self.isolation_forest.predict(data)
                if_anomalies = (if_predictions == -1).astype(int)
                results['model_predictions']['isolation_forest'] = if_anomalies.tolist()
                results['confidence_scores']['isolation_forest'] = 0.85
            
            # Autoencoder detection
            if self.autoencoder:
                reconstructed = self.autoencoder.predict(data)
                ae_errors = np.mean(np.square(data - reconstructed), axis=1)
                ae_threshold = np.percentile(ae_errors, 90)
                ae_anomalies = (ae_errors > ae_threshold).astype(int)
                results['model_predictions']['autoencoder'] = ae_anomalies.tolist()
                results['confidence_scores']['autoencoder'] = 0.80
            
            # LSTM detection
            if self.lstm_model:
                data_lstm = data.reshape(-1, 1, 10)
                lstm_predictions = self.lstm_model.predict(data_lstm)
                lstm_anomalies = (lstm_predictions > 0.5).astype(int).flatten()
                results['model_predictions']['lstm'] = lstm_anomalies.tolist()
                results['confidence_scores']['lstm'] = 0.90
            
            # Ensemble decision
            ensemble_anomalies = np.zeros(len(data))
            if 'isolation_forest' in results['model_predictions']:
                ensemble_anomalies += np.array(results['model_predictions']['isolation_forest'])
            if 'autoencoder' in results['model_predictions']:
                ensemble_anomalies += np.array(results['model_predictions']['autoencoder'])
            if 'lstm' in results['model_predictions']:
                ensemble_anomalies += np.array(results['model_predictions']['lstm'])
            
            # Final anomaly decision (majority vote)
            final_anomalies = (ensemble_anomalies >= 2).astype(int)
            results['anomalies_detected'] = int(np.sum(final_anomalies))
            results['model_predictions']['ensemble'] = final_anomalies.tolist()
            
            # Generate recommendations
            if results['anomalies_detected'] > 0:
                results['recommendations'].append("Investigate detected anomalies immediately")
                results['recommendations'].append("Review network traffic patterns")
                results['recommendations'].append("Check for potential security breaches")
                
                # Trigger adaptive deception based on anomaly detection
                self._trigger_adaptive_deception(results)
            
            # Store results in Redis
            self._store_results(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return {'error': str(e)}
    
    def _store_results(self, results: Dict):
        """Store analysis results in Redis"""
        try:
            key = f"analysis_results:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, 3600, json.dumps(results))  # Store for 1 hour
            logger.info(f"Analysis results stored in Redis with key: {key}")
        except Exception as e:
            logger.error(f"Error storing results in Redis: {e}")
    
    def _trigger_adaptive_deception(self, anomaly_results: Dict):
        """Trigger adaptive deception based on anomaly detection"""
        try:
            # Create event data for adaptive deception engine
            event_data = {
                'session_id': f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'action': 'anomaly_detected',
                'target': 'network_traffic',
                'success': True,
                'timestamp': datetime.now().isoformat(),
                'anomaly_score': float(anomaly_results['anomalies_detected']) / float(anomaly_results['data_points']),
                'confidence_scores': anomaly_results['confidence_scores'],
                'model_predictions': anomaly_results['model_predictions']
            }
            
            # Send to adaptive deception engine
            try:
                response = requests.post(
                    f"{self.adaptive_deception_url}/process_event",
                    json=event_data,
                    timeout=5
                )
                
                if response.status_code == 200:
                    logger.info("Successfully triggered adaptive deception")
                else:
                    logger.warning(f"Adaptive deception responded with status {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.warning(f"Could not reach adaptive deception service: {e}")
                
        except Exception as e:
            logger.error(f"Error triggering adaptive deception: {e}")
    
    def get_model_status(self) -> Dict:
        """Get status of all models"""
        return {
            'lstm_model': self.lstm_model is not None,
            'isolation_forest': self.isolation_forest is not None,
            'autoencoder': self.autoencoder is not None,
            'adaptive_deception_enabled': True,
            'model_path': self.model_path,
            'last_updated': datetime.now().isoformat()
        }

# Flask API for the behavioral analysis engine
from flask import Flask, request, jsonify

app = Flask(__name__)
analysis_engine = BehavioralAnalysisEngine()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'behavioral_analysis',
        'models_loaded': analysis_engine.get_model_status()
    })

@app.route('/train', methods=['POST'])
def train_models():
    """Train all models"""
    try:
        success = analysis_engine.train_models()
        return jsonify({
            'success': success,
            'message': 'Models trained successfully' if success else 'Training failed'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/detect', methods=['POST'])
def detect_anomalies():
    """Detect anomalies in input data"""
    try:
        data = request.get_json()
        if not data or 'data' not in data:
            return jsonify({'error': 'No data provided'}), 400
        
        input_data = np.array(data['data'])
        results = analysis_engine.detect_anomalies(input_data)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/status', methods=['GET'])
def get_status():
    """Get model status"""
    return jsonify(analysis_engine.get_model_status())

@app.route('/retrain', methods=['POST'])
def retrain_model():
    """Retrain a specific model with new data (Section 6 - Task 24)"""
    try:
        data = request.get_json()
        model_name = data.get('model_name', 'lstm')
        features = np.array(data.get('features', []))
        labels = np.array(data.get('labels', []))
        
        if len(features) == 0 or len(labels) == 0:
            return jsonify({'error': 'Features and labels required'}), 400
        
        # Retrain the specified model
        if model_name == 'lstm':
            success = analysis_engine._retrain_lstm(features, labels)
        elif model_name == 'isolation_forest':
            success = analysis_engine._retrain_isolation_forest(features, labels)
        elif model_name == 'autoencoder':
            success = analysis_engine._retrain_autoencoder(features, labels)
        else:
            return jsonify({'error': f'Unknown model: {model_name}'}), 400
        
        if success:
            # Evaluate performance
            performance = analysis_engine._evaluate_model_performance(model_name, features, labels)
            
            return jsonify({
                'success': True,
                'model_name': model_name,
                'model_path': f"{analysis_engine.model_path}/{model_name}_model.h5" if model_name != 'isolation_forest' else f"{analysis_engine.model_path}/isolation_forest.pkl",
                'performance_metrics': performance,
                'training_samples': len(labels)
            })
        else:
            return jsonify({'error': 'Retraining failed'}), 500
            
    except Exception as e:
        logger.error(f"Error retraining model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/evaluate', methods=['POST'])
def evaluate_model():
    """Evaluate model performance on test data (Section 6 - Task 24)"""
    try:
        data = request.get_json()
        model_name = data.get('model_name', 'lstm')
        features = np.array(data.get('features', []))
        labels = np.array(data.get('labels', []))
        
        if len(features) == 0 or len(labels) == 0:
            return jsonify({'error': 'Features and labels required'}), 400
        
        performance = analysis_engine._evaluate_model_performance(model_name, features, labels)
        return jsonify(performance)
        
    except Exception as e:
        logger.error(f"Error evaluating model: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Train models on startup if they don't exist
    if not all(analysis_engine.get_model_status().values()):
        logger.info("Training models on startup...")
        analysis_engine.train_models()
    
    app.run(host='0.0.0.0', port=5001, debug=True)
