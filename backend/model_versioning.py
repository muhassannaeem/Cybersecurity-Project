"""
Model Versioning System - Track ML model versions and performance
Section 6 - Task 24: Model Versioning and Rollback
"""

import os
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc

# Configure logging
logger = logging.getLogger(__name__)


class ModelVersionManager:
    """Manage ML model versions with tracking and rollback capabilities"""
    
    def __init__(self, db_session: Session, model_base_path: str = "/app/models"):
        """
        Initialize model version manager
        
        Args:
            db_session: SQLAlchemy database session
            model_base_path: Base path where models are stored
        """
        self.db = db_session
        self.model_base_path = model_base_path
        os.makedirs(model_base_path, exist_ok=True)
    
    def create_version(self, model_name: str, model_path: str, 
                      performance_metrics: Dict, training_data_size: int = None,
                      validation_metrics: Dict = None, test_metrics: Dict = None,
                      metadata: Dict = None) -> Optional[int]:
        """
        Create a new model version with metadata
        
        Args:
            model_name: Name of the model (lstm, isolation_forest, autoencoder)
            model_path: Path to the model file
            performance_metrics: Dictionary with performance metrics (accuracy, precision, recall, F1, etc.)
            training_data_size: Number of samples used for training
            validation_metrics: Validation set performance metrics
            test_metrics: Test set performance metrics
            metadata: Additional metadata
        
        Returns:
            ID of created version record, or None on error
        """
        try:
            from app import ModelVersion
            
            # Get next version number
            last_version = self.db.query(ModelVersion).filter(
                ModelVersion.model_name == model_name
            ).order_by(desc(ModelVersion.version)).first()
            
            next_version = (last_version.version + 1) if last_version else 1
            
            # Get previous active version
            previous_active = self.db.query(ModelVersion).filter(
                and_(
                    ModelVersion.model_name == model_name,
                    ModelVersion.is_active == True
                )
            ).first()
            
            previous_version_id = previous_active.id if previous_active else None
            
            # Calculate model file hash
            model_hash = None
            file_size = None
            if os.path.exists(model_path):
                file_size = os.path.getsize(model_path)
                with open(model_path, 'rb') as f:
                    model_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Create version record
            version = ModelVersion(
                model_name=model_name,
                version=next_version,
                training_data_size=training_data_size,
                performance_metrics=performance_metrics,
                validation_metrics=validation_metrics or {},
                test_metrics=test_metrics or {},
                file_path=model_path,
                file_size_bytes=file_size,
                model_hash=model_hash,
                previous_version_id=previous_version_id,
                metadata=metadata or {}
            )
            
            self.db.add(version)
            self.db.commit()
            self.db.refresh(version)
            
            logger.info(f"Created model version: {model_name} v{next_version} (ID: {version.id})")
            return version.id
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating model version: {e}")
            return None
    
    def get_active_version(self, model_name: str) -> Optional[Dict]:
        """Get the currently active version of a model"""
        try:
            from app import ModelVersion
            
            version = self.db.query(ModelVersion).filter(
                and_(
                    ModelVersion.model_name == model_name,
                    ModelVersion.is_active == True
                )
            ).first()
            
            if version:
                return self._version_to_dict(version)
            return None
            
        except Exception as e:
            logger.error(f"Error getting active version: {e}")
            return None
    
    def get_version_history(self, model_name: str, limit: int = 10) -> List[Dict]:
        """Get version history for a model"""
        try:
            from app import ModelVersion
            
            versions = self.db.query(ModelVersion).filter(
                ModelVersion.model_name == model_name
            ).order_by(desc(ModelVersion.version)).limit(limit).all()
            
            return [self._version_to_dict(v) for v in versions]
            
        except Exception as e:
            logger.error(f"Error getting version history: {e}")
            return []
    
    def activate_version(self, model_name: str, version: int) -> bool:
        """
        Activate a specific version (deactivates previous active version)
        
        Args:
            model_name: Name of the model
            version: Version number to activate
        
        Returns:
            True if successful, False otherwise
        """
        try:
            from app import ModelVersion
            
            # Deactivate current active version
            self.db.query(ModelVersion).filter(
                and_(
                    ModelVersion.model_name == model_name,
                    ModelVersion.is_active == True
                )
            ).update({'is_active': False, 'deactivated_at': datetime.utcnow()})
            
            # Activate new version
            result = self.db.query(ModelVersion).filter(
                and_(
                    ModelVersion.model_name == model_name,
                    ModelVersion.version == version
                )
            ).update({
                'is_active': True,
                'activated_at': datetime.utcnow()
            })
            
            self.db.commit()
            
            if result > 0:
                logger.info(f"Activated {model_name} version {version}")
                return True
            else:
                logger.warning(f"Version {version} not found for {model_name}")
                return False
                
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error activating version: {e}")
            return False
    
    def rollback_to_version(self, model_name: str, version: int) -> bool:
        """
        Rollback to a previous version
        
        Args:
            model_name: Name of the model
            version: Version number to rollback to
        
        Returns:
            True if successful, False otherwise
        """
        try:
            from app import ModelVersion
            
            # Get target version
            target_version = self.db.query(ModelVersion).filter(
                and_(
                    ModelVersion.model_name == model_name,
                    ModelVersion.version == version
                )
            ).first()
            
            if not target_version:
                logger.error(f"Version {version} not found for {model_name}")
                return False
            
            # Check if model file exists
            if not os.path.exists(target_version.file_path):
                logger.error(f"Model file not found: {target_version.file_path}")
                return False
            
            # Activate the target version (this deactivates current)
            success = self.activate_version(model_name, version)
            
            if success:
                logger.info(f"Rolled back {model_name} to version {version}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error rolling back version: {e}")
            return False
    
    def compare_versions(self, model_name: str, version1: int, version2: int) -> Optional[Dict]:
        """
        Compare two model versions
        
        Args:
            model_name: Name of the model
            version1: First version number
            version2: Second version number
        
        Returns:
            Dictionary with comparison results, or None on error
        """
        try:
            from app import ModelVersion
            
            v1 = self.db.query(ModelVersion).filter(
                and_(
                    ModelVersion.model_name == model_name,
                    ModelVersion.version == version1
                )
            ).first()
            
            v2 = self.db.query(ModelVersion).filter(
                and_(
                    ModelVersion.model_name == model_name,
                    ModelVersion.version == version2
                )
            ).first()
            
            if not v1 or not v2:
                return None
            
            # Extract metrics for comparison
            v1_metrics = v1.performance_metrics or {}
            v2_metrics = v2.performance_metrics or {}
            
            comparison = {
                'version1': {
                    'version': v1.version,
                    'created_at': v1.created_at.isoformat() if v1.created_at else None,
                    'is_active': v1.is_active,
                    'metrics': v1_metrics
                },
                'version2': {
                    'version': v2.version,
                    'created_at': v2.created_at.isoformat() if v2.created_at else None,
                    'is_active': v2.is_active,
                    'metrics': v2_metrics
                },
                'differences': {}
            }
            
            # Calculate differences for common metrics
            for metric in ['accuracy', 'precision', 'recall', 'f1_score', 'false_positive_rate']:
                v1_val = v1_metrics.get(metric)
                v2_val = v2_metrics.get(metric)
                
                if v1_val is not None and v2_val is not None:
                    diff = v2_val - v1_val
                    comparison['differences'][metric] = {
                        'absolute': diff,
                        'percent': (diff / v1_val * 100) if v1_val != 0 else 0
                    }
            
            return comparison
            
        except Exception as e:
            logger.error(f"Error comparing versions: {e}")
            return None
    
    def should_rollback(self, new_version_id: int, previous_version_id: int, 
                       degradation_threshold: float = 0.05) -> Tuple[bool, str]:
        """
        Determine if a rollback should be performed based on performance comparison
        
        Args:
            new_version_id: ID of the new model version
            previous_version_id: ID of the previous model version
            degradation_threshold: Maximum allowed performance degradation (default 5%)
        
        Returns:
            Tuple of (should_rollback: bool, reason: str)
        """
        try:
            from app import ModelVersion
            
            new_version = self.db.query(ModelVersion).filter(
                ModelVersion.id == new_version_id
            ).first()
            
            previous_version = self.db.query(ModelVersion).filter(
                ModelVersion.id == previous_version_id
            ).first()
            
            if not new_version or not previous_version:
                return False, "Version not found"
            
            new_metrics = new_version.performance_metrics or {}
            prev_metrics = previous_version.performance_metrics or {}
            
            # Check key metrics
            key_metrics = ['accuracy', 'f1_score']
            degradations = []
            
            for metric in key_metrics:
                new_val = new_metrics.get(metric)
                prev_val = prev_metrics.get(metric)
                
                if new_val is not None and prev_val is not None:
                    degradation = (prev_val - new_val) / prev_val
                    if degradation > degradation_threshold:
                        degradations.append(f"{metric}: {degradation*100:.2f}% worse")
            
            if degradations:
                reason = f"Performance degraded: {', '.join(degradations)}"
                return True, reason
            
            return False, "Performance acceptable"
            
        except Exception as e:
            logger.error(f"Error checking rollback condition: {e}")
            return False, f"Error: {str(e)}"
    
    def _version_to_dict(self, version) -> Dict:
        """Convert ModelVersion object to dictionary"""
        return {
            'id': version.id,
            'model_name': version.model_name,
            'version': version.version,
            'created_at': version.created_at.isoformat() if version.created_at else None,
            'training_data_size': version.training_data_size,
            'performance_metrics': version.performance_metrics,
            'validation_metrics': version.validation_metrics,
            'test_metrics': version.test_metrics,
            'file_path': version.file_path,
            'file_size_bytes': version.file_size_bytes,
            'model_hash': version.model_hash,
            'is_active': version.is_active,
            'previous_version_id': version.previous_version_id,
            'activated_at': version.activated_at.isoformat() if version.activated_at else None,
            'deactivated_at': version.deactivated_at.isoformat() if version.deactivated_at else None,
            'metadata': version.metadata
        }

