"""
Automated Model Retraining Pipeline
Section 6 - Task 24: Automated model retraining with real data
"""

import os
import json
import logging
import uuid
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

# Configure logging
logger = logging.getLogger(__name__)


class ModelRetrainingPipeline:
    """Automated model retraining pipeline with performance tracking"""
    
    def __init__(self, db_session: Session, model_base_path: str = "/app/models",
                 behavioral_analysis_url: str = "http://behavioral_analysis:5001"):
        """
        Initialize retraining pipeline
        
        Args:
            db_session: SQLAlchemy database session
            model_base_path: Base path where models are stored
            behavioral_analysis_url: URL of behavioral analysis service
        """
        self.db = db_session
        self.model_base_path = model_base_path
        self.behavioral_analysis_url = behavioral_analysis_url
        self.is_retraining = False
        self.retraining_lock = threading.Lock()
    
    def schedule_retraining(self, model_name: str, schedule: str = "weekly",
                           trigger_type: str = "scheduled", trigger_reason: str = None) -> Optional[str]:
        """
        Schedule a retraining job
        
        Args:
            model_name: Name of the model to retrain
            schedule: Schedule type (weekly, monthly, manual)
            trigger_type: Type of trigger (scheduled, performance, manual, data_available)
            trigger_reason: Reason for retraining
        
        Returns:
            Job ID if successful, None otherwise
        """
        try:
            from app import RetrainingJob
            
            job_id = f"retrain_{model_name}_{uuid.uuid4().hex[:8]}"
            
            job = RetrainingJob(
                job_id=job_id,
                model_name=model_name,
                status='pending',
                trigger_type=trigger_type,
                trigger_reason=trigger_reason or f"Scheduled {schedule} retraining",
                triggered_by='system',
                metadata={'schedule': schedule}
            )
            
            self.db.add(job)
            self.db.commit()
            self.db.refresh(job)
            
            logger.info(f"Scheduled retraining job: {job_id} for {model_name}")
            return job_id
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error scheduling retraining: {e}")
            return None
    
    def retrain_model(self, model_name: str, training_data: Dict,
                     previous_version_id: Optional[int] = None) -> Optional[Dict]:
        """
        Retrain a model with new data
        
        Args:
            model_name: Name of the model to retrain
            training_data: Dictionary with 'features' and 'labels' arrays
            previous_version_id: ID of previous model version
        
        Returns:
            Dictionary with retraining results, or None on error
        """
        try:
            import requests
            from model_versioning import ModelVersionManager
            from training_data_collector import TrainingDataCollector
            
            if self.is_retraining:
                return {'error': 'Retraining already in progress'}
            
            with self.retraining_lock:
                self.is_retraining = True
                
                try:
                    logger.info(f"Starting retraining for {model_name}")
                    
                    # Get previous version info
                    version_manager = ModelVersionManager(self.db, self.model_base_path)
                    previous_version = None
                    if previous_version_id:
                        from app import ModelVersion
                        previous_version = self.db.query(ModelVersion).filter(
                            ModelVersion.id == previous_version_id
                        ).first()
                    
                    # Call behavioral analysis service to retrain
                    retrain_response = requests.post(
                        f"{self.behavioral_analysis_url}/retrain",
                        json={
                            'model_name': model_name,
                            'features': training_data['features'].tolist() if hasattr(training_data['features'], 'tolist') else training_data['features'],
                            'labels': training_data['labels'].tolist() if hasattr(training_data['labels'], 'tolist') else training_data['labels']
                        },
                        timeout=3600  # 1 hour timeout
                    )
                    
                    if retrain_response.status_code != 200:
                        return {'error': f"Retraining failed: {retrain_response.text}"}
                    
                    retrain_result = retrain_response.json()
                    
                    # Get new model path
                    new_model_path = retrain_result.get('model_path')
                    if not new_model_path:
                        new_model_path = f"{self.model_base_path}/{model_name}_retrained.h5"
                    
                    # Evaluate new model performance
                    performance_metrics = retrain_result.get('performance_metrics', {})
                    
                    # Create new version
                    new_version_id = version_manager.create_version(
                        model_name=model_name,
                        model_path=new_model_path,
                        performance_metrics=performance_metrics,
                        training_data_size=len(training_data['labels']),
                        validation_metrics=retrain_result.get('validation_metrics', {}),
                        test_metrics=retrain_result.get('test_metrics', {}),
                        metadata=training_data.get('metadata', {})
                    )
                    
                    if not new_version_id:
                        return {'error': 'Failed to create model version'}
                    
                    # Check if rollback is needed
                    if previous_version:
                        should_rollback, reason = version_manager.should_rollback(
                            new_version_id, previous_version.id
                        )
                        
                        if should_rollback:
                            logger.warning(f"Rollback needed: {reason}")
                            version_manager.rollback_to_version(model_name, previous_version.version)
                            return {
                                'success': False,
                                'new_version_id': new_version_id,
                                'rollback_performed': True,
                                'rollback_reason': reason
                            }
                    
                    # Activate new version
                    from app import ModelVersion
                    new_version = self.db.query(ModelVersion).filter(
                        ModelVersion.id == new_version_id
                    ).first()
                    
                    if new_version:
                        version_manager.activate_version(model_name, new_version.version)
                    
                    return {
                        'success': True,
                        'new_version_id': new_version_id,
                        'new_version': new_version.version if new_version else None,
                        'performance_metrics': performance_metrics,
                        'rollback_performed': False
                    }
                    
                finally:
                    self.is_retraining = False
                    
        except Exception as e:
            logger.error(f"Error retraining model: {e}")
            return {'error': str(e)}
    
    def execute_retraining_job(self, job_id: str) -> Dict:
        """
        Execute a retraining job
        
        Args:
            job_id: ID of the retraining job
        
        Returns:
            Dictionary with job execution results
        """
        try:
            from app import RetrainingJob
            from training_data_collector import TrainingDataCollector
            
            job = self.db.query(RetrainingJob).filter(
                RetrainingJob.job_id == job_id
            ).first()
            
            if not job:
                return {'error': 'Job not found'}
            
            if job.status not in ['pending', 'failed']:
                return {'error': f'Job is not in a runnable state: {job.status}'}
            
            # Update job status
            job.status = 'running'
            job.started_at = datetime.utcnow()
            self.db.commit()
            
            try:
                # Collect training data
                collector = TrainingDataCollector(self.db)
                training_data = collector.prepare_training_dataset()
                
                if not training_data:
                    job.status = 'failed'
                    job.error_message = 'Failed to collect sufficient training data'
                    job.completed_at = datetime.utcnow()
                    self.db.commit()
                    return {'error': 'Insufficient training data'}
                
                # Get previous version
                from model_versioning import ModelVersionManager
                version_manager = ModelVersionManager(self.db, self.model_base_path)
                previous_version = version_manager.get_active_version(job.model_name)
                previous_version_id = previous_version['id'] if previous_version else None
                
                # Retrain model
                result = self.retrain_model(
                    job.model_name,
                    training_data,
                    previous_version_id
                )
                
                # Update job with results
                job.completed_at = datetime.utcnow()
                job.duration_seconds = int((job.completed_at - job.started_at).total_seconds())
                
                if result.get('success'):
                    job.status = 'completed'
                    job.new_version_id = result.get('new_version_id')
                    job.previous_version_id = previous_version_id
                    job.performance_comparison = result.get('performance_metrics', {})
                    job.rollback_performed = result.get('rollback_performed', False)
                    job.rollback_reason = result.get('rollback_reason')
                    job.real_attack_samples = training_data['metadata'].get('attack_samples', 0)
                    job.benign_samples = training_data['metadata'].get('benign_samples', 0)
                    job.training_data_size = training_data['metadata'].get('total_samples', 0)
                else:
                    job.status = 'failed'
                    job.error_message = result.get('error', 'Unknown error')
                
                self.db.commit()
                
                return result
                
            except Exception as e:
                job.status = 'failed'
                job.error_message = str(e)
                job.completed_at = datetime.utcnow()
                self.db.commit()
                logger.error(f"Error executing retraining job {job_id}: {e}")
                return {'error': str(e)}
                
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error executing retraining job: {e}")
            return {'error': str(e)}
    
    def evaluate_model_performance(self, model_name: str, test_data: Dict) -> Dict:
        """
        Evaluate model performance on test data
        
        Args:
            model_name: Name of the model
            test_data: Dictionary with 'features' and 'labels'
        
        Returns:
            Dictionary with performance metrics
        """
        try:
            import requests
            
            response = requests.post(
                f"{self.behavioral_analysis_url}/evaluate",
                json={
                    'model_name': model_name,
                    'features': test_data['features'].tolist() if hasattr(test_data['features'], 'tolist') else test_data['features'],
                    'labels': test_data['labels'].tolist() if hasattr(test_data['labels'], 'tolist') else test_data['labels']
                },
                timeout=300
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f"Evaluation failed: {response.text}"}
                
        except Exception as e:
            logger.error(f"Error evaluating model: {e}")
            return {'error': str(e)}

