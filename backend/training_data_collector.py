"""
Training Data Collector - Collect and prepare real attack data for model retraining
Section 6 - Task 24: Incorporate real captured data
"""

import os
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

# Configure logging
logger = logging.getLogger(__name__)


class TrainingDataCollector:
    """Collect and prepare training data from real attacks and benign traffic"""
    
    def __init__(self, db_session: Session):
        """
        Initialize training data collector
        
        Args:
            db_session: SQLAlchemy database session
        """
        self.db = db_session
    
    def collect_labeled_attack_data(self, days: int = 30, min_samples: int = 100) -> Tuple[np.ndarray, np.ndarray]:
        """
        Collect labeled attack data from evaluation metrics and detection events
        
        Args:
            days: Number of days to look back
            min_samples: Minimum number of samples required
        
        Returns:
            Tuple of (features, labels) where labels are 1 for attacks
        """
        try:
            from app import EvaluationMetric, DetectionEvent
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Collect from evaluation metrics (known attacks)
            eval_metrics = self.db.query(EvaluationMetric).filter(
                EvaluationMetric.timestamp >= cutoff_date,
                EvaluationMetric.detected == True
            ).all()
            
            # Collect from detection events
            detection_events = self.db.query(DetectionEvent).filter(
                DetectionEvent.timestamp >= cutoff_date
            ).all()
            
            features = []
            labels = []
            
            # Process evaluation metrics
            for metric in eval_metrics:
                feature = self._extract_features_from_metric(metric)
                if feature is not None:
                    features.append(feature)
                    labels.append(1)  # Attack
            
            # Process detection events
            for event in detection_events:
                feature = self._extract_features_from_event(event)
                if feature is not None:
                    features.append(feature)
                    labels.append(1)  # Attack
            
            if len(features) < min_samples:
                logger.warning(f"Only collected {len(features)} attack samples, need {min_samples}")
                return np.array([]), np.array([])
            
            return np.array(features), np.array(labels)
            
        except Exception as e:
            logger.error(f"Error collecting attack data: {e}")
            return np.array([]), np.array([])
    
    def collect_benign_traffic_data(self, days: int = 30, min_samples: int = 100) -> Tuple[np.ndarray, np.ndarray]:
        """
        Collect labeled benign traffic data from false positive corrections
        
        Args:
            days: Number of days to look back
            min_samples: Minimum number of samples required
        
        Returns:
            Tuple of (features, labels) where labels are 0 for benign
        """
        try:
            from app import FalsePositiveEvent
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Collect false positives that were corrected to benign
            false_positives = self.db.query(FalsePositiveEvent).filter(
                FalsePositiveEvent.timestamp >= cutoff_date,
                FalsePositiveEvent.corrected_label == 'benign'
            ).all()
            
            features = []
            labels = []
            
            for fp in false_positives:
                feature = self._extract_features_from_false_positive(fp)
                if feature is not None:
                    features.append(feature)
                    labels.append(0)  # Benign
            
            if len(features) < min_samples:
                logger.warning(f"Only collected {len(features)} benign samples, need {min_samples}")
                return np.array([]), np.array([])
            
            return np.array(features), np.array(labels)
            
        except Exception as e:
            logger.error(f"Error collecting benign data: {e}")
            return np.array([]), np.array([])
    
    def prepare_training_dataset(self, attack_days: int = 30, benign_days: int = 30,
                                 min_attack_samples: int = 100, min_benign_samples: int = 500) -> Optional[Dict]:
        """
        Prepare complete training dataset with both attack and benign samples
        
        Args:
            attack_days: Days to look back for attack data
            benign_days: Days to look back for benign data
            min_attack_samples: Minimum attack samples required
            min_benign_samples: Minimum benign samples required
        
        Returns:
            Dictionary with training data and metadata, or None on error
        """
        try:
            logger.info("Collecting attack data...")
            attack_features, attack_labels = self.collect_labeled_attack_data(attack_days, min_attack_samples)
            
            logger.info("Collecting benign data...")
            benign_features, benign_labels = self.collect_benign_traffic_data(benign_days, min_benign_samples)
            
            if len(attack_features) == 0 or len(benign_features) == 0:
                logger.error("Insufficient data collected")
                return None
            
            # Combine datasets
            all_features = np.vstack([attack_features, benign_features])
            all_labels = np.hstack([attack_labels, benign_labels])
            
            # Shuffle
            indices = np.random.permutation(len(all_labels))
            all_features = all_features[indices]
            all_labels = all_labels[indices]
            
            dataset = {
                'features': all_features,
                'labels': all_labels,
                'metadata': {
                    'total_samples': len(all_labels),
                    'attack_samples': len(attack_labels),
                    'benign_samples': len(benign_labels),
                    'attack_ratio': len(attack_labels) / len(all_labels),
                    'collected_at': datetime.utcnow().isoformat(),
                    'attack_days': attack_days,
                    'benign_days': benign_days
                }
            }
            
            logger.info(f"Prepared training dataset: {len(all_labels)} samples ({len(attack_labels)} attacks, {len(benign_labels)} benign)")
            return dataset
            
        except Exception as e:
            logger.error(f"Error preparing training dataset: {e}")
            return None
    
    def _extract_features_from_metric(self, metric) -> Optional[np.ndarray]:
        """Extract feature vector from evaluation metric"""
        try:
            # Create 10-feature vector from metric data
            features = [
                float(metric.detection_latency) if metric.detection_latency else 0.0,
                float(metric.false_positive_rate) if metric.false_positive_rate else 0.0,
                float(metric.attacker_engagement_time) if metric.attacker_engagement_time else 0.0,
                float(metric.decoy_believability_score) if metric.decoy_believability_score else 0.0,
                float(metric.threat_actor_attribution_accuracy) if metric.threat_actor_attribution_accuracy else 0.0,
                float(metric.overall_score) if metric.overall_score else 0.0,
                1.0 if metric.detected else 0.0,
                hash(metric.scenario_name) % 1000 / 1000.0,  # Normalized scenario hash
                hash(metric.target_host) % 1000 / 1000.0 if metric.target_host else 0.0,
                0.5  # Placeholder for additional feature
            ]
            return np.array(features)
        except Exception as e:
            logger.error(f"Error extracting features from metric: {e}")
            return None
    
    def _extract_features_from_event(self, event) -> Optional[np.ndarray]:
        """Extract feature vector from detection event"""
        try:
            features = [
                float(event.detection_latency_seconds) if event.detection_latency_seconds else 0.0,
                float(event.confidence_score) if event.confidence_score else 0.0,
                hash(event.attack_type) % 1000 / 1000.0 if event.attack_type else 0.0,
                hash(event.source_ip) % 1000 / 1000.0 if event.source_ip else 0.0,
                hash(event.destination_ip) % 1000 / 1000.0 if event.destination_ip else 0.0,
                hash(event.detected_by) % 1000 / 1000.0 if event.detected_by else 0.0,
                1.0,  # Known attack
                0.0,  # Not from evaluation
                0.0,  # Placeholder
                0.0   # Placeholder
            ]
            return np.array(features)
        except Exception as e:
            logger.error(f"Error extracting features from event: {e}")
            return None
    
    def _extract_features_from_false_positive(self, fp) -> Optional[np.ndarray]:
        """Extract feature vector from false positive event"""
        try:
            features = [
                0.0,  # No detection latency (benign)
                float(fp.confidence_score) if fp.confidence_score else 0.0,
                hash(fp.event_type) % 1000 / 1000.0 if fp.event_type else 0.0,
                hash(fp.source_ip) % 1000 / 1000.0 if fp.source_ip else 0.0,
                hash(fp.destination_ip) % 1000 / 1000.0 if fp.destination_ip else 0.0,
                hash(fp.detected_by) % 1000 / 1000.0 if fp.detected_by else 0.0,
                0.0,  # Not an attack
                0.0,  # Not from evaluation
                0.0,  # Placeholder
                0.0   # Placeholder
            ]
            return np.array(features)
        except Exception as e:
            logger.error(f"Error extracting features from false positive: {e}")
            return None

