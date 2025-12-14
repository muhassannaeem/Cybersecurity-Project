"""
Metrics Service - Centralized service for metrics collection and persistence
Section 6 - Task 21-22: Evaluation Metrics & Persistence
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy import func, and_, or_, Integer, cast
from sqlalchemy.orm import Session

# Configure logging
logger = logging.getLogger(__name__)


class MetricsService:
    """Centralized service for metrics collection and persistence"""
    
    def __init__(self, db_session: Session):
        """
        Initialize metrics service with database session
        
        Args:
            db_session: SQLAlchemy database session
        """
        self.db = db_session
    
    # =====================================================
    # Evaluation Metrics (Task 21)
    # =====================================================
    
    def store_evaluation_metric(self, metric_data: Dict) -> Optional[int]:
        """
        Store evaluation metric in database
        
        Args:
            metric_data: Dictionary containing metric data:
                - scenario_name: Test scenario name
                - test_id: Unique test identifier
                - detection_latency: Detection latency in seconds
                - false_positive_rate: False positive rate (0.0-1.0)
                - attacker_engagement_time: Engagement time in seconds
                - decoy_believability_score: Believability score (0.0-1.0)
                - threat_actor_attribution_accuracy: Attribution accuracy (0.0-1.0)
                - overall_score: Overall performance score
                - detected: Whether attack was detected
                - target_host: Target host
                - metadata: Additional context
        
        Returns:
            ID of created metric record, or None on error
        """
        try:
            # Import here to avoid circular imports
            from app import EvaluationMetric
            
            metric = EvaluationMetric(
                timestamp=metric_data.get('timestamp', datetime.utcnow()),
                scenario_name=metric_data.get('scenario_name'),
                test_id=metric_data.get('test_id'),
                detection_latency=metric_data.get('detection_latency'),
                false_positive_rate=metric_data.get('false_positive_rate'),
                attacker_engagement_time=metric_data.get('attacker_engagement_time'),
                decoy_believability_score=metric_data.get('decoy_believability_score'),
                threat_actor_attribution_accuracy=metric_data.get('threat_actor_attribution_accuracy'),
                overall_score=metric_data.get('overall_score'),
                detected=metric_data.get('detected', False),
                target_host=metric_data.get('target_host'),
                extra_metadata=metric_data.get('metadata')
            )
            
            self.db.add(metric)
            self.db.commit()
            self.db.refresh(metric)
            
            logger.info(f"Stored evaluation metric: {metric.id} for scenario {metric.scenario_name}")
            return metric.id
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error storing evaluation metric: {e}")
            return None
    
    def store_detection_event(self, event_data: Dict) -> Optional[int]:
        """
        Store detection event with latency calculation
        
        Args:
            event_data: Dictionary containing event data:
                - attack_start_time: When attack started
                - detection_time: When attack was detected
                - source_ip: Source IP address
                - destination_ip: Destination IP address
                - attack_type: Type of attack
                - detected_by: Service that detected it
                - confidence_score: Detection confidence
                - threat_id: Reference to threat record
                - alert_id: Reference to alert record
                - metadata: Additional context
        
        Returns:
            ID of created event record, or None on error
        """
        try:
            from app import DetectionEvent
            
            attack_start = event_data.get('attack_start_time')
            detection_time = event_data.get('detection_time', datetime.utcnow())
            
            # Calculate latency
            if isinstance(attack_start, str):
                attack_start = datetime.fromisoformat(attack_start.replace('Z', '+00:00'))
            if isinstance(detection_time, str):
                detection_time = datetime.fromisoformat(detection_time.replace('Z', '+00:00'))
            
            latency = (detection_time - attack_start).total_seconds()
            
            event = DetectionEvent(
                timestamp=datetime.utcnow(),
                attack_start_time=attack_start,
                detection_time=detection_time,
                detection_latency_seconds=latency,
                source_ip=event_data.get('source_ip'),
                destination_ip=event_data.get('destination_ip'),
                attack_type=event_data.get('attack_type'),
                detected_by=event_data.get('detected_by'),
                confidence_score=event_data.get('confidence_score'),
                threat_id=event_data.get('threat_id'),
                alert_id=event_data.get('alert_id'),
                extra_metadata=event_data.get('metadata')
            )
            
            self.db.add(event)
            self.db.commit()
            self.db.refresh(event)
            
            logger.info(f"Stored detection event: {event.id} with latency {latency:.3f}s")
            return event.id
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error storing detection event: {e}")
            return None
    
    def store_false_positive_event(self, event_data: Dict) -> Optional[int]:
        """
        Store false positive event
        
        Args:
            event_data: Dictionary containing false positive data
        
        Returns:
            ID of created event record, or None on error
        """
        try:
            from app import FalsePositiveEvent
            
            event = FalsePositiveEvent(
                timestamp=event_data.get('timestamp', datetime.utcnow()),
                event_type=event_data.get('event_type'),
                source_ip=event_data.get('source_ip'),
                destination_ip=event_data.get('destination_ip'),
                false_positive_type=event_data.get('false_positive_type'),
                original_label=event_data.get('original_label'),
                corrected_label=event_data.get('corrected_label', 'benign'),
                confidence_score=event_data.get('confidence_score'),
                detected_by=event_data.get('detected_by'),
                corrected_by=event_data.get('corrected_by'),
                correction_timestamp=event_data.get('correction_timestamp'),
                extra_metadata=event_data.get('metadata')
            )
            
            self.db.add(event)
            self.db.commit()
            self.db.refresh(event)
            
            logger.info(f"Stored false positive event: {event.id}")
            return event.id
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error storing false positive event: {e}")
            return None
    
    def store_decoy_interaction(self, interaction_data: Dict) -> Optional[int]:
        """
        Store decoy interaction with engagement metrics
        
        Args:
            interaction_data: Dictionary containing interaction data
        
        Returns:
            ID of created interaction record, or None on error
        """
        try:
            from app import DecoyInteraction
            
            interaction_start = interaction_data.get('interaction_start')
            interaction_end = interaction_data.get('interaction_end')
            
            # Calculate engagement duration
            duration = None
            if interaction_start and interaction_end:
                if isinstance(interaction_start, str):
                    interaction_start = datetime.fromisoformat(interaction_start.replace('Z', '+00:00'))
                if isinstance(interaction_end, str):
                    interaction_end = datetime.fromisoformat(interaction_end.replace('Z', '+00:00'))
                duration = (interaction_end - interaction_start).total_seconds()
            
            interaction = DecoyInteraction(
                timestamp=datetime.utcnow(),
                decoy_id=interaction_data.get('decoy_id'),
                decoy_type=interaction_data.get('decoy_type'),
                attacker_ip=interaction_data.get('attacker_ip'),
                interaction_start=interaction_start or datetime.utcnow(),
                interaction_end=interaction_end,
                engagement_duration=duration,
                actions_count=interaction_data.get('actions_count', 0),
                depth_score=interaction_data.get('depth_score'),
                believability_score=interaction_data.get('believability_score'),
                repeat_visits=interaction_data.get('repeat_visits', 0),
                first_action=interaction_data.get('first_action'),
                last_action=interaction_data.get('last_action'),
                actions_taken=interaction_data.get('actions_taken'),
                extra_metadata=interaction_data.get('metadata')
            )
            
            self.db.add(interaction)
            self.db.commit()
            self.db.refresh(interaction)
            
            logger.info(f"Stored decoy interaction: {interaction.id}")
            return interaction.id
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error storing decoy interaction: {e}")
            return None
    
    def store_attribution_accuracy(self, accuracy_data: Dict) -> Optional[int]:
        """
        Store threat actor attribution accuracy
        
        Args:
            accuracy_data: Dictionary containing attribution accuracy data
        
        Returns:
            ID of created accuracy record, or None on error
        """
        try:
            from app import ThreatAttributionAccuracy
            
            # Calculate accuracy score
            technique_matches = accuracy_data.get('technique_matches', 0)
            technique_total = accuracy_data.get('technique_total', 0)
            accuracy_score = technique_matches / technique_total if technique_total > 0 else 0.0
            
            accuracy = ThreatAttributionAccuracy(
                timestamp=datetime.utcnow(),
                test_id=accuracy_data.get('test_id'),
                evaluation_metric_id=accuracy_data.get('evaluation_metric_id'),
                ground_truth_actor=accuracy_data.get('ground_truth_actor'),
                attributed_actor=accuracy_data.get('attributed_actor'),
                ground_truth_techniques=accuracy_data.get('ground_truth_techniques'),
                attributed_techniques=accuracy_data.get('attributed_techniques'),
                actor_match=accuracy_data.get('actor_match'),
                technique_matches=technique_matches,
                technique_total=technique_total,
                accuracy_score=accuracy_score,
                confidence_score=accuracy_data.get('confidence_score'),
                extra_metadata=accuracy_data.get('metadata')
            )
            
            self.db.add(accuracy)
            self.db.commit()
            self.db.refresh(accuracy)
            
            logger.info(f"Stored attribution accuracy: {accuracy.id} with score {accuracy_score:.4f}")
            return accuracy.id
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error storing attribution accuracy: {e}")
            return None
    
    # =====================================================
    # Metrics Queries for Trend Analysis (Task 22)
    # =====================================================
    
    def get_detection_latency_trends(self, days: int = 30) -> List[Dict]:
        """Get detection latency trends over time"""
        try:
            from app import DetectionEvent
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Group by day and calculate statistics
            results = self.db.query(
                func.date(DetectionEvent.timestamp).label('date'),
                func.avg(DetectionEvent.detection_latency_seconds).label('avg_latency'),
                func.min(DetectionEvent.detection_latency_seconds).label('min_latency'),
                func.max(DetectionEvent.detection_latency_seconds).label('max_latency'),
                func.count(DetectionEvent.id).label('count')
            ).filter(
                DetectionEvent.timestamp >= cutoff_date
            ).group_by(
                func.date(DetectionEvent.timestamp)
            ).order_by(
                func.date(DetectionEvent.timestamp)
            ).all()
            
            return [
                {
                    'date': str(r.date),
                    'avg_latency': float(r.avg_latency) if r.avg_latency else 0,
                    'min_latency': float(r.min_latency) if r.min_latency else 0,
                    'max_latency': float(r.max_latency) if r.max_latency else 0,
                    'count': r.count
                }
                for r in results
            ]
            
        except Exception as e:
            logger.error(f"Error getting detection latency trends: {e}")
            return []
    
    def get_false_positive_rate_trends(self, days: int = 30) -> List[Dict]:
        """Get false positive rate trends over time"""
        try:
            from app import FalsePositiveEvent, DetectionEvent
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Count false positives per day
            false_positives = self.db.query(
                func.date(FalsePositiveEvent.timestamp).label('date'),
                func.count(FalsePositiveEvent.id).label('fp_count')
            ).filter(
                FalsePositiveEvent.timestamp >= cutoff_date
            ).group_by(
                func.date(FalsePositiveEvent.timestamp)
            ).subquery()
            
            # Count total detections per day
            total_detections = self.db.query(
                func.date(DetectionEvent.timestamp).label('date'),
                func.count(DetectionEvent.id).label('total_count')
            ).filter(
                DetectionEvent.timestamp >= cutoff_date
            ).group_by(
                func.date(DetectionEvent.timestamp)
            ).subquery()
            
            # Join and calculate rate
            results = self.db.query(
                func.coalesce(false_positives.c.date, total_detections.c.date).label('date'),
                func.coalesce(false_positives.c.fp_count, 0).label('fp_count'),
                func.coalesce(total_detections.c.total_count, 0).label('total_count')
            ).outerjoin(
                total_detections, false_positives.c.date == total_detections.c.date
            ).all()
            
            return [
                {
                    'date': str(r.date),
                    'false_positive_count': r.fp_count,
                    'total_detections': r.total_count,
                    'false_positive_rate': (r.fp_count / r.total_count) if r.total_count > 0 else 0.0
                }
                for r in results
            ]
            
        except Exception as e:
            logger.error(f"Error getting false positive rate trends: {e}")
            return []
    
    def get_decoy_engagement_metrics(self, days: int = 30) -> Dict:
        """Get decoy engagement metrics"""
        try:
            from app import DecoyInteraction
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            stats = self.db.query(
                func.avg(DecoyInteraction.engagement_duration).label('avg_duration'),
                func.avg(DecoyInteraction.believability_score).label('avg_believability'),
                func.avg(DecoyInteraction.depth_score).label('avg_depth'),
                func.count(DecoyInteraction.id).label('total_interactions'),
                func.sum(DecoyInteraction.repeat_visits).label('total_repeat_visits')
            ).filter(
                DecoyInteraction.timestamp >= cutoff_date
            ).first()
            
            return {
                'avg_engagement_duration': float(stats.avg_duration) if stats.avg_duration else 0,
                'avg_believability_score': float(stats.avg_believability) if stats.avg_believability else 0,
                'avg_depth_score': float(stats.avg_depth) if stats.avg_depth else 0,
                'total_interactions': stats.total_interactions or 0,
                'total_repeat_visits': stats.total_repeat_visits or 0
            }
            
        except Exception as e:
            logger.error(f"Error getting decoy engagement metrics: {e}")
            return {}
    
    def get_attribution_accuracy_metrics(self, days: int = 30) -> Dict:
        """Get threat attribution accuracy metrics"""
        try:
            from app import ThreatAttributionAccuracy
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            stats = self.db.query(
                func.avg(ThreatAttributionAccuracy.accuracy_score).label('avg_accuracy'),
                func.avg(ThreatAttributionAccuracy.confidence_score).label('avg_confidence'),
                func.count(ThreatAttributionAccuracy.id).label('total_tests'),
                func.sum(cast(ThreatAttributionAccuracy.actor_match, Integer)).label('actor_matches')
            ).filter(
                ThreatAttributionAccuracy.timestamp >= cutoff_date
            ).first()
            
            return {
                'avg_accuracy': float(stats.avg_accuracy) if stats.avg_accuracy else 0,
                'avg_confidence': float(stats.avg_confidence) if stats.avg_confidence else 0,
                'total_tests': stats.total_tests or 0,
                'actor_match_rate': (stats.actor_matches / stats.total_tests) if stats.total_tests > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Error getting attribution accuracy metrics: {e}")
            return {}
    
    def get_evaluation_summary(self, scenario_name: Optional[str] = None, days: int = 30) -> Dict:
        """Get summary of evaluation metrics"""
        try:
            from app import EvaluationMetric
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            query = self.db.query(EvaluationMetric).filter(
                EvaluationMetric.timestamp >= cutoff_date
            )
            
            if scenario_name:
                query = query.filter(EvaluationMetric.scenario_name == scenario_name)
            
            metrics = query.all()
            
            if not metrics:
                return {
                    'total_tests': 0,
                    'avg_detection_latency': 0,
                    'avg_false_positive_rate': 0,
                    'avg_engagement_time': 0,
                    'avg_believability': 0,
                    'avg_attribution_accuracy': 0,
                    'detection_rate': 0
                }
            
            detection_latencies = [float(m.detection_latency) for m in metrics if m.detection_latency]
            false_positive_rates = [float(m.false_positive_rate) for m in metrics if m.false_positive_rate]
            engagement_times = [float(m.attacker_engagement_time) for m in metrics if m.attacker_engagement_time]
            believability_scores = [float(m.decoy_believability_score) for m in metrics if m.decoy_believability_score]
            attribution_accuracies = [float(m.threat_actor_attribution_accuracy) for m in metrics if m.threat_actor_attribution_accuracy]
            detected_count = sum(1 for m in metrics if m.detected)
            
            return {
                'total_tests': len(metrics),
                'avg_detection_latency': sum(detection_latencies) / len(detection_latencies) if detection_latencies else 0,
                'avg_false_positive_rate': sum(false_positive_rates) / len(false_positive_rates) if false_positive_rates else 0,
                'avg_engagement_time': sum(engagement_times) / len(engagement_times) if engagement_times else 0,
                'avg_believability': sum(believability_scores) / len(believability_scores) if believability_scores else 0,
                'avg_attribution_accuracy': sum(attribution_accuracies) / len(attribution_accuracies) if attribution_accuracies else 0,
                'detection_rate': detected_count / len(metrics) if metrics else 0
            }
            
        except Exception as e:
            logger.error(f"Error getting evaluation summary: {e}")
            return {}

