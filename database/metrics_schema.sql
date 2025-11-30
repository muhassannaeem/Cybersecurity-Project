-- =====================================================
-- Cybersecurity Project - Metrics Schema
-- =====================================================
-- This script creates tables for evaluation metrics,
-- model versioning, and retraining tracking
-- =====================================================

-- =====================================================
-- EVALUATION METRICS TABLE
-- =====================================================
-- Stores comprehensive evaluation test results
CREATE TABLE IF NOT EXISTS evaluation_metrics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scenario_name VARCHAR(100) NOT NULL COMMENT 'Test scenario name',
    test_id VARCHAR(255) UNIQUE COMMENT 'Unique test identifier',
    
    -- Core Metrics (Task 21)
    detection_latency DECIMAL(10, 3) COMMENT 'Time from attack start to detection (seconds)',
    false_positive_rate DECIMAL(5, 4) COMMENT 'Percentage of benign events misclassified (0.0-1.0)',
    attacker_engagement_time DECIMAL(10, 3) COMMENT 'Duration attackers spent in decoys (seconds)',
    decoy_believability_score DECIMAL(5, 4) COMMENT 'Believability score (0.0-1.0)',
    threat_actor_attribution_accuracy DECIMAL(5, 4) COMMENT 'Attribution accuracy (0.0-1.0)',
    
    -- Additional Metrics
    overall_score DECIMAL(5, 4) COMMENT 'Overall performance score (0.0-1.0)',
    detected BOOLEAN DEFAULT FALSE COMMENT 'Whether attack was detected',
    target_host VARCHAR(255) COMMENT 'Target host for the test',
    
    -- Metadata
    metadata JSON COMMENT 'Additional test details and context',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_timestamp (timestamp),
    INDEX idx_scenario_name (scenario_name),
    INDEX idx_test_id (test_id),
    INDEX idx_detected (detected),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- DETECTION EVENTS TABLE
-- =====================================================
-- Tracks detection latency from real attack data
CREATE TABLE IF NOT EXISTS detection_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attack_start_time TIMESTAMP NOT NULL COMMENT 'When the attack actually started',
    detection_time TIMESTAMP NOT NULL COMMENT 'When the attack was detected',
    detection_latency_seconds DECIMAL(10, 3) NOT NULL COMMENT 'Calculated latency',
    
    -- Attack Details
    source_ip VARCHAR(45) COMMENT 'Source IP address',
    destination_ip VARCHAR(45) COMMENT 'Destination IP address',
    attack_type VARCHAR(100) COMMENT 'Type of attack',
    detected_by VARCHAR(100) COMMENT 'Service that detected it (traffic_monitor, behavioral_analysis, etc.)',
    confidence_score DECIMAL(5, 4) COMMENT 'Detection confidence (0.0-1.0)',
    
    -- Additional Context
    threat_id INT COMMENT 'Reference to threat record',
    alert_id INT COMMENT 'Reference to alert record',
    metadata JSON COMMENT 'Additional detection details',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes
    INDEX idx_timestamp (timestamp),
    INDEX idx_attack_start_time (attack_start_time),
    INDEX idx_detection_time (detection_time),
    INDEX idx_source_ip (source_ip),
    INDEX idx_attack_type (attack_type),
    INDEX idx_detected_by (detected_by),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- FALSE POSITIVE EVENTS TABLE
-- =====================================================
-- Tracks false positive classifications
CREATE TABLE IF NOT EXISTS false_positive_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(100) NOT NULL COMMENT 'Type of event (threat, anomaly, alert)',
    source_ip VARCHAR(45) COMMENT 'Source IP address',
    destination_ip VARCHAR(45) COMMENT 'Destination IP address',
    
    -- False Positive Details
    false_positive_type VARCHAR(100) COMMENT 'Category of false positive',
    original_label VARCHAR(100) COMMENT 'Label assigned by system',
    corrected_label VARCHAR(100) COMMENT 'Correct label (benign)',
    confidence_score DECIMAL(5, 4) COMMENT 'Original confidence score',
    
    -- Context
    detected_by VARCHAR(100) COMMENT 'Service that made the false positive',
    corrected_by VARCHAR(100) COMMENT 'Who/what corrected it',
    correction_timestamp TIMESTAMP COMMENT 'When it was corrected',
    
    -- Metadata
    metadata JSON COMMENT 'Additional context',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes
    INDEX idx_timestamp (timestamp),
    INDEX idx_event_type (event_type),
    INDEX idx_source_ip (source_ip),
    INDEX idx_false_positive_type (false_positive_type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- DECOY INTERACTIONS TABLE
-- =====================================================
-- Tracks attacker engagement with decoys
CREATE TABLE IF NOT EXISTS decoy_interactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    decoy_id INT COMMENT 'Reference to decoy',
    decoy_type VARCHAR(50) COMMENT 'Type of decoy',
    attacker_ip VARCHAR(45) NOT NULL COMMENT 'Attacker IP address',
    
    -- Engagement Timing
    interaction_start TIMESTAMP NOT NULL COMMENT 'When interaction started',
    interaction_end TIMESTAMP COMMENT 'When interaction ended',
    engagement_duration DECIMAL(10, 3) COMMENT 'Total engagement time (seconds)',
    
    -- Engagement Metrics
    actions_count INT DEFAULT 0 COMMENT 'Number of actions taken',
    depth_score DECIMAL(5, 4) COMMENT 'Depth of interaction (0.0-1.0)',
    believability_score DECIMAL(5, 4) COMMENT 'Believability score (0.0-1.0)',
    repeat_visits INT DEFAULT 0 COMMENT 'Number of repeat visits',
    
    -- Interaction Details
    first_action VARCHAR(255) COMMENT 'First action taken',
    last_action VARCHAR(255) COMMENT 'Last action taken',
    actions_taken JSON COMMENT 'List of actions taken',
    
    -- Metadata
    metadata JSON COMMENT 'Additional interaction details',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes
    INDEX idx_timestamp (timestamp),
    INDEX idx_decoy_id (decoy_id),
    INDEX idx_attacker_ip (attacker_ip),
    INDEX idx_interaction_start (interaction_start),
    INDEX idx_engagement_duration (engagement_duration),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- THREAT ATTRIBUTION ACCURACY TABLE
-- =====================================================
-- Tracks accuracy of threat actor attribution
CREATE TABLE IF NOT EXISTS threat_attribution_accuracy (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    test_id VARCHAR(255) COMMENT 'Reference to evaluation test',
    evaluation_metric_id INT COMMENT 'Reference to evaluation_metrics',
    
    -- Attribution Details
    ground_truth_actor VARCHAR(255) COMMENT 'Actual threat actor (ground truth)',
    attributed_actor VARCHAR(255) COMMENT 'Attributed threat actor',
    ground_truth_techniques JSON COMMENT 'Actual MITRE ATT&CK techniques',
    attributed_techniques JSON COMMENT 'Attributed MITRE ATT&CK techniques',
    
    -- Accuracy Metrics
    actor_match BOOLEAN COMMENT 'Whether actor attribution was correct',
    technique_matches INT COMMENT 'Number of correctly attributed techniques',
    technique_total INT COMMENT 'Total number of techniques',
    accuracy_score DECIMAL(5, 4) COMMENT 'Overall accuracy (0.0-1.0)',
    
    -- Confidence
    confidence_score DECIMAL(5, 4) COMMENT 'Attribution confidence',
    
    -- Metadata
    metadata JSON COMMENT 'Additional attribution details',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes
    INDEX idx_timestamp (timestamp),
    INDEX idx_test_id (test_id),
    INDEX idx_evaluation_metric_id (evaluation_metric_id),
    INDEX idx_actor_match (actor_match),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- MODEL VERSIONS TABLE
-- =====================================================
-- Tracks ML model versions and performance
CREATE TABLE IF NOT EXISTS model_versions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL COMMENT 'Model name (lstm, isolation_forest, autoencoder)',
    version INT NOT NULL COMMENT 'Version number',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Training Details
    training_data_size INT COMMENT 'Number of samples used for training',
    training_start_time TIMESTAMP COMMENT 'When training started',
    training_end_time TIMESTAMP COMMENT 'When training completed',
    training_duration_seconds INT COMMENT 'Training duration',
    
    -- Performance Metrics
    performance_metrics JSON COMMENT 'Model performance (accuracy, precision, recall, F1, etc.)',
    validation_metrics JSON COMMENT 'Validation set performance',
    test_metrics JSON COMMENT 'Test set performance',
    
    -- Model Storage
    file_path VARCHAR(500) COMMENT 'Path to model file',
    file_size_bytes BIGINT COMMENT 'Model file size',
    model_hash VARCHAR(64) COMMENT 'SHA256 hash of model file',
    
    -- Version Management
    is_active BOOLEAN DEFAULT FALSE COMMENT 'Whether this is the active version',
    previous_version_id INT COMMENT 'Reference to previous version',
    activated_at TIMESTAMP COMMENT 'When this version was activated',
    deactivated_at TIMESTAMP COMMENT 'When this version was deactivated',
    
    -- Metadata
    metadata JSON COMMENT 'Additional version details',
    created_at_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Unique constraint
    UNIQUE KEY unique_model_version (model_name, version),
    
    -- Indexes
    INDEX idx_model_name (model_name),
    INDEX idx_version (version),
    INDEX idx_is_active (is_active),
    INDEX idx_created_at (created_at_timestamp),
    INDEX idx_previous_version_id (previous_version_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- RETRAINING JOBS TABLE
-- =====================================================
-- Tracks automated model retraining jobs
CREATE TABLE IF NOT EXISTS retraining_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    job_id VARCHAR(255) UNIQUE NOT NULL COMMENT 'Unique job identifier',
    model_name VARCHAR(100) NOT NULL COMMENT 'Model being retrained',
    status VARCHAR(50) DEFAULT 'pending' COMMENT 'pending, running, completed, failed, cancelled',
    
    -- Job Timing
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP COMMENT 'When job started',
    completed_at TIMESTAMP COMMENT 'When job completed',
    duration_seconds INT COMMENT 'Job duration',
    
    -- Trigger Information
    trigger_type VARCHAR(100) COMMENT 'What triggered retraining (scheduled, performance, manual, data_available)',
    trigger_reason TEXT COMMENT 'Reason for retraining',
    triggered_by VARCHAR(100) COMMENT 'Who/what triggered it (system, user_id, etc.)',
    
    -- Training Data
    training_data_size INT COMMENT 'Number of samples in training data',
    real_attack_samples INT COMMENT 'Number of real attack samples',
    benign_samples INT COMMENT 'Number of benign samples',
    synthetic_samples INT COMMENT 'Number of synthetic samples',
    
    -- Results
    new_version_id INT COMMENT 'Reference to new model version',
    previous_version_id INT COMMENT 'Reference to previous model version',
    performance_comparison JSON COMMENT 'Before/after performance comparison',
    rollback_performed BOOLEAN DEFAULT FALSE COMMENT 'Whether rollback was needed',
    rollback_reason TEXT COMMENT 'Reason for rollback if performed',
    
    -- Error Handling
    error_message TEXT COMMENT 'Error message if job failed',
    error_traceback TEXT COMMENT 'Full error traceback',
    
    -- Metadata
    metadata JSON COMMENT 'Additional job details',
    
    -- Indexes
    INDEX idx_job_id (job_id),
    INDEX idx_model_name (model_name),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    INDEX idx_trigger_type (trigger_type),
    INDEX idx_new_version_id (new_version_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

-- Composite indexes for common queries
CREATE INDEX idx_eval_metrics_scenario_time ON evaluation_metrics(scenario_name, timestamp);
CREATE INDEX idx_detection_events_time_range ON detection_events(attack_start_time, detection_time);
CREATE INDEX idx_decoy_interactions_decoy_time ON decoy_interactions(decoy_id, interaction_start);
CREATE INDEX idx_model_versions_name_active ON model_versions(model_name, is_active);

-- =====================================================
-- VIEWS FOR ANALYTICS
-- =====================================================

-- View for recent evaluation metrics summary
CREATE OR REPLACE VIEW recent_evaluation_summary AS
SELECT 
    scenario_name,
    COUNT(*) as total_tests,
    AVG(detection_latency) as avg_detection_latency,
    AVG(false_positive_rate) as avg_false_positive_rate,
    AVG(attacker_engagement_time) as avg_engagement_time,
    AVG(decoy_believability_score) as avg_believability,
    AVG(threat_actor_attribution_accuracy) as avg_attribution_accuracy,
    AVG(overall_score) as avg_overall_score,
    SUM(CASE WHEN detected = TRUE THEN 1 ELSE 0 END) as detections_count
FROM evaluation_metrics
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY scenario_name;

-- View for model version performance comparison
CREATE OR REPLACE VIEW model_version_comparison AS
SELECT 
    mv1.model_name,
    mv1.version as current_version,
    mv2.version as previous_version,
    mv1.performance_metrics->>'$.accuracy' as current_accuracy,
    mv2.performance_metrics->>'$.accuracy' as previous_accuracy,
    mv1.created_at_timestamp as current_created_at,
    mv2.created_at_timestamp as previous_created_at
FROM model_versions mv1
JOIN model_versions mv2 ON mv1.previous_version_id = mv2.id
WHERE mv1.is_active = TRUE;

-- =====================================================
-- SUCCESS MESSAGE
-- =====================================================
SELECT '✅ Metrics schema created successfully!' AS status;
SELECT 'Tables: evaluation_metrics, detection_events, false_positive_events, decoy_interactions, threat_attribution_accuracy, model_versions, retraining_jobs' AS info;

