"""
Retraining Triggers - Connect evaluation metrics to retraining logic
Section 6 - Task 25: Connect evaluation results to retraining
"""

import os
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_, func

# Configure logging
logger = logging.getLogger(__name__)


class RetrainingTriggerSystem:
    """Monitor evaluation metrics and trigger retraining when conditions are met"""
    
    def __init__(self, db_session: Session, retraining_pipeline, 
                 check_interval: int = 3600):  # Check every hour
        """
        Initialize retraining trigger system
        
        Args:
            db_session: SQLAlchemy database session
            retraining_pipeline: ModelRetrainingPipeline instance
            check_interval: Interval in seconds between checks
        """
        self.db = db_session
        self.retraining_pipeline = retraining_pipeline
        self.check_interval = check_interval
        self.running = False
        self.background_thread = None
        
        # Configuration thresholds
        self.performance_degradation_threshold = float(os.getenv('RETRAIN_DEGRADATION_THRESHOLD', '0.1'))  # 10%
        self.min_data_samples = int(os.getenv('RETRAIN_MIN_SAMPLES', '500'))
        self.scheduled_retrain_interval_days = int(os.getenv('RETRAIN_INTERVAL_DAYS', '7'))  # Weekly
    
    def start(self):
        """Start background monitoring thread"""
        if self.running:
            logger.warning("Retraining trigger system already running")
            return
        
        self.running = True
        self.background_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.background_thread.start()
        logger.info("Retraining trigger system started")
    
    def stop(self):
        """Stop background monitoring thread"""
        self.running = False
        if self.background_thread:
            self.background_thread.join(timeout=5)
        logger.info("Retraining trigger system stopped")
    
    def _monitoring_loop(self):
        """Background loop that checks retraining conditions"""
        # Import app for context
        from app import app
        
        while self.running:
            try:
                # Use app context for database access in background thread
                with app.app_context():
                    self.check_retraining_conditions()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                import traceback
                logger.error(traceback.format_exc())
                time.sleep(60)  # Wait 1 minute before retrying
    
    def check_retraining_conditions(self):
        """Check if retraining should be triggered for any model"""
        try:
            models = ['lstm', 'isolation_forest', 'autoencoder']
            
            for model_name in models:
                # Check performance-based trigger
                if self._check_performance_degradation(model_name):
                    self.trigger_retraining(model_name, 'performance', 
                                          'Performance degraded below threshold')
                    continue
                
                # Check data-based trigger
                if self._check_sufficient_new_data(model_name):
                    self.trigger_retraining(model_name, 'data_available',
                                          'Sufficient new labeled data available')
                    continue
                
                # Check scheduled trigger
                if self._check_scheduled_retrain(model_name):
                    self.trigger_retraining(model_name, 'scheduled',
                                          f'Scheduled retraining (every {self.scheduled_retrain_interval_days} days)')
                    continue
                    
        except Exception as e:
            logger.error(f"Error checking retraining conditions: {e}")
    
    def _check_performance_degradation(self, model_name: str) -> bool:
        """Check if model performance has degraded"""
        try:
            from app import EvaluationMetric, ModelVersion
            from metrics_service import MetricsService
            
            # Get active model version
            active_version = self.db.query(ModelVersion).filter(
                and_(
                    ModelVersion.model_name == model_name,
                    ModelVersion.is_active == True
                )
            ).first()
            
            if not active_version:
                return False
            
            # Get recent evaluation metrics (last 7 days)
            cutoff_date = datetime.utcnow() - timedelta(days=7)
            recent_metrics = self.db.query(EvaluationMetric).filter(
                EvaluationMetric.timestamp >= cutoff_date
            ).all()
            
            if len(recent_metrics) < 10:  # Need minimum samples
                return False
            
            # Calculate average performance
            avg_overall_score = sum(float(m.overall_score) for m in recent_metrics if m.overall_score) / len(recent_metrics)
            avg_detection_rate = sum(1 for m in recent_metrics if m.detected) / len(recent_metrics)
            
            # Get baseline performance from model version
            baseline_metrics = active_version.performance_metrics or {}
            baseline_accuracy = baseline_metrics.get('accuracy', 0.8)
            
            # Check if performance degraded
            if avg_overall_score < (baseline_accuracy * (1 - self.performance_degradation_threshold)):
                logger.warning(f"Performance degradation detected for {model_name}: "
                             f"avg_score={avg_overall_score:.3f}, baseline={baseline_accuracy:.3f}")
                return True
            
            if avg_detection_rate < 0.7:  # Less than 70% detection rate
                logger.warning(f"Low detection rate for {model_name}: {avg_detection_rate:.3f}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking performance degradation: {e}")
            return False
    
    def _check_sufficient_new_data(self, model_name: str) -> bool:
        """Check if sufficient new labeled data is available"""
        try:
            from app import EvaluationMetric, DetectionEvent, FalsePositiveEvent, RetrainingJob
            from sqlalchemy import and_
            
            # Check last retraining time
            last_retrain = self.db.query(RetrainingJob).filter(
                and_(
                    RetrainingJob.model_name == model_name,
                    RetrainingJob.status == 'completed'
                )
            ).order_by(RetrainingJob.completed_at.desc()).first()
            
            if last_retrain:
                data_cutoff = last_retrain.completed_at
            else:
                data_cutoff = datetime.utcnow() - timedelta(days=30)
            
            # Count new samples
            new_eval_metrics = self.db.query(EvaluationMetric).filter(
                EvaluationMetric.timestamp >= data_cutoff,
                EvaluationMetric.detected == True
            ).count()
            
            new_detections = self.db.query(DetectionEvent).filter(
                DetectionEvent.timestamp >= data_cutoff
            ).count()
            
            new_false_positives = self.db.query(FalsePositiveEvent).filter(
                FalsePositiveEvent.timestamp >= data_cutoff
            ).count()
            
            total_new_samples = new_eval_metrics + new_detections + new_false_positives
            
            if total_new_samples >= self.min_data_samples:
                logger.info(f"Sufficient new data for {model_name}: {total_new_samples} samples")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking new data: {e}")
            return False
    
    def _check_scheduled_retrain(self, model_name: str) -> bool:
        """Check if scheduled retraining is due"""
        try:
            from app import RetrainingJob
            from sqlalchemy import and_
            
            # Get last completed retraining
            last_retrain = self.db.query(RetrainingJob).filter(
                and_(
                    RetrainingJob.model_name == model_name,
                    RetrainingJob.status == 'completed',
                    RetrainingJob.trigger_type == 'scheduled'
                )
            ).order_by(RetrainingJob.completed_at.desc()).first()
            
            if not last_retrain:
                # Never retrained, check if we have enough data
                return self._check_sufficient_new_data(model_name)
            
            # Check if interval has passed
            if not last_retrain.completed_at:
                # If no completion time, check if we have enough data
                return self._check_sufficient_new_data(model_name)
            
            days_since_retrain = (datetime.utcnow() - last_retrain.completed_at).days
            
            if days_since_retrain >= self.scheduled_retrain_interval_days:
                logger.info(f"Scheduled retraining due for {model_name} ({days_since_retrain} days since last)")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking scheduled retrain: {e}")
            return False
    
    def trigger_retraining(self, model_name: str, trigger_type: str, reason: str) -> Optional[str]:
        """
        Trigger a retraining job
        
        Args:
            model_name: Name of the model to retrain
            trigger_type: Type of trigger (performance, data_available, scheduled, manual)
            reason: Reason for retraining
        
        Returns:
            Job ID if successful, None otherwise
        """
        try:
            # Check if there's already a pending/running job
            from app import RetrainingJob
            from sqlalchemy import and_
            existing_job = self.db.query(RetrainingJob).filter(
                and_(
                    RetrainingJob.model_name == model_name,
                    RetrainingJob.status.in_(['pending', 'running'])
                )
            ).first()
            
            if existing_job:
                logger.info(f"Retraining job already exists for {model_name}: {existing_job.job_id}")
                return existing_job.job_id
            
            # Schedule retraining job
            job_id = self.retraining_pipeline.schedule_retraining(
                model_name=model_name,
                trigger_type=trigger_type,
                trigger_reason=reason
            )
            
            if job_id:
                logger.info(f"Triggered retraining for {model_name}: {job_id} ({trigger_type})")
                
                # Execute job in background thread
                execution_thread = threading.Thread(
                    target=self._execute_job_background,
                    args=(job_id,),
                    daemon=True
                )
                execution_thread.start()
            
            return job_id
            
        except Exception as e:
            logger.error(f"Error triggering retraining: {e}")
            return None
    
    def _execute_job_background(self, job_id: str):
        """Execute retraining job in background thread"""
        # Import app for context
        from app import app
        
        try:
            # Use app context for database access in background thread
            with app.app_context():
                result = self.retraining_pipeline.execute_retraining_job(job_id)
                logger.info(f"Retraining job {job_id} completed: {result.get('success', False)}")
        except Exception as e:
            logger.error(f"Error executing retraining job {job_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def evaluate_retraining_need(self, metrics: Dict) -> Dict:
        """
        Evaluate if retraining is needed based on metrics
        
        Args:
            metrics: Dictionary with evaluation metrics
        
        Returns:
            Dictionary with evaluation results
        """
        try:
            evaluation = {
                'retraining_needed': False,
                'reasons': [],
                'recommended_models': []
            }
            
            # Check overall performance
            overall_score = metrics.get('avg_overall_score', 0)
            detection_rate = metrics.get('detection_rate', 0)
            false_positive_rate = metrics.get('avg_false_positive_rate', 0)
            
            if overall_score < 0.7:
                evaluation['retraining_needed'] = True
                evaluation['reasons'].append(f"Low overall score: {overall_score:.3f}")
                evaluation['recommended_models'].extend(['lstm', 'isolation_forest', 'autoencoder'])
            
            if detection_rate < 0.7:
                evaluation['retraining_needed'] = True
                evaluation['reasons'].append(f"Low detection rate: {detection_rate:.3f}")
                evaluation['recommended_models'].extend(['lstm', 'autoencoder'])
            
            if false_positive_rate > 0.2:
                evaluation['retraining_needed'] = True
                evaluation['reasons'].append(f"High false positive rate: {false_positive_rate:.3f}")
                evaluation['recommended_models'].extend(['isolation_forest', 'autoencoder'])
            
            return evaluation
            
        except Exception as e:
            logger.error(f"Error evaluating retraining need: {e}")
            return {'retraining_needed': False, 'error': str(e)}

