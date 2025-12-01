@echo off
REM Cybersecurity Platform Kubernetes Deployment Script for Windows
REM This script builds and deploys the entire cybersecurity platform to Kubernetes

setlocal enabledelayedexpansion

REM Configuration
set NAMESPACE=cybersecurity-platform
set REGISTRY_PREFIX=cybersecurity
set TAG=latest
set ENVIRONMENT=development
set SKIP_BUILD=false

REM Parse command line arguments
:parse_args
if "%~1"=="" goto :check_prerequisites
if "%~1"=="--cleanup" (
    call :cleanup
    exit /b 0
)
if "%~1"=="--skip-build" (
    set SKIP_BUILD=true
    shift
    goto :parse_args
)
if "%~1"=="--help" (
    echo Usage: %0 [OPTIONS]
    echo Options:
    echo   --cleanup         Clean up existing deployment
    echo   --skip-build      Skip Docker image building
    echo   --help           Show this help message
    exit /b 0
)
shift
goto :parse_args

:check_prerequisites
echo [INFO] Checking prerequisites...

REM Check if kubectl is installed
kubectl version --client >nul 2>&1
if errorlevel 1 (
    echo [ERROR] kubectl is not installed. Please install kubectl.
    exit /b 1
)

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker.
    exit /b 1
)

REM Check if cluster is accessible
kubectl cluster-info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Cannot connect to Kubernetes cluster. Please check your kubeconfig.
    exit /b 1
)

echo [SUCCESS] Prerequisites check passed
goto :build_images

:build_images
if "%SKIP_BUILD%"=="true" (
    echo [INFO] Skipping Docker image building
    goto :create_namespace
)

echo [INFO] Building Docker images...

REM Build backend
echo [INFO] Building backend...
docker build -t %REGISTRY_PREFIX%-backend:%TAG% ./backend
if errorlevel 1 (
    echo [ERROR] Failed to build backend image
    exit /b 1
)

REM Build frontend
echo [INFO] Building frontend...
docker build -t %REGISTRY_PREFIX%-frontend:%TAG% ./frontend
if errorlevel 1 (
    echo [ERROR] Failed to build frontend image
    exit /b 1
)

REM Build microservices
echo [INFO] Building behavioral-analysis...
if exist "./backend/behavioral_analysis/Dockerfile" (
    docker build -t %REGISTRY_PREFIX%-behavioral-analysis:%TAG% ./backend/behavioral_analysis
)

echo [INFO] Building decoy-generator...
if exist "./backend/decoy_generator/Dockerfile" (
    docker build -t %REGISTRY_PREFIX%-decoy-generator:%TAG% ./backend/decoy_generator
)

echo [INFO] Building traffic-monitor...
if exist "./backend/traffic_monitor/Dockerfile" (
    docker build -t %REGISTRY_PREFIX%-traffic-monitor:%TAG% ./backend/traffic_monitor
)

echo [INFO] Building threat-attribution...
if exist "./backend/threat_attribution/Dockerfile" (
    docker build -t %REGISTRY_PREFIX%-threat-attribution:%TAG% ./backend/threat_attribution
)

echo [INFO] Building visualization-dashboard...
if exist "./backend/visualization_dashboard/Dockerfile" (
    docker build -t %REGISTRY_PREFIX%-visualization-dashboard:%TAG% ./backend/visualization_dashboard
)

echo [INFO] Building threat-intelligence...
if exist "./backend/threat_intelligence/Dockerfile" (
    docker build -t %REGISTRY_PREFIX%-threat-intelligence:%TAG% ./backend/threat_intelligence
)

echo [INFO] Building adaptive-deception...
if exist "./backend/adaptive_deception/Dockerfile" (
    docker build -t %REGISTRY_PREFIX%-adaptive-deception:%TAG% ./backend/adaptive_deception
)

echo [INFO] Building evaluation-engine...
if exist "./evaluation/Dockerfile" (
    docker build -t %REGISTRY_PREFIX%-evaluation-engine:%TAG% ./evaluation
)

echo [SUCCESS] All Docker images built successfully
goto :create_namespace

:create_namespace
echo [INFO] Creating namespace: %NAMESPACE%
kubectl create namespace %NAMESPACE% --dry-run=client -o yaml | kubectl apply -f -
echo [SUCCESS] Namespace %NAMESPACE% ready
goto :deploy_to_k8s

:deploy_to_k8s
echo [INFO] Deploying to Kubernetes environment: %ENVIRONMENT%

set OVERLAY_PATH=./k8s/overlays/%ENVIRONMENT%
if not exist "%OVERLAY_PATH%" (
    echo [ERROR] Environment overlay not found: %OVERLAY_PATH%
    exit /b 1
)

echo [INFO] Applying Kubernetes manifests...
kubectl apply -k %OVERLAY_PATH%
if errorlevel 1 (
    echo [ERROR] Failed to apply Kubernetes manifests
    exit /b 1
)

echo [SUCCESS] Kubernetes manifests applied
goto :wait_for_deployments

:wait_for_deployments
echo [INFO] Waiting for deployments to be ready...

echo [INFO] Waiting for PostgreSQL...
kubectl wait --for=condition=ready pod -l app=postgresql -n %NAMESPACE% --timeout=300s

echo [INFO] Waiting for Redis...
kubectl wait --for=condition=available deployment/redis -n %NAMESPACE% --timeout=300s

echo [INFO] Waiting for Elasticsearch...
kubectl wait --for=condition=ready pod -l app=elasticsearch -n %NAMESPACE% --timeout=300s

echo [INFO] Waiting for backend...
kubectl wait --for=condition=available deployment/backend -n %NAMESPACE% --timeout=300s

echo [INFO] Waiting for frontend...
kubectl wait --for=condition=available deployment/frontend -n %NAMESPACE% --timeout=300s

echo [SUCCESS] All deployments are ready
goto :show_status

:show_status
echo [INFO] Deployment Status:
echo.

echo [INFO] Pods:
kubectl get pods -n %NAMESPACE% -o wide
echo.

echo [INFO] Services:
kubectl get services -n %NAMESPACE%
echo.

echo [INFO] Ingress:
kubectl get ingress -n %NAMESPACE%
echo.

echo [INFO] For local testing, use port-forward:
echo kubectl port-forward -n %NAMESPACE% svc/frontend 3000:3000
echo.

echo [SUCCESS] Cybersecurity Platform deployed successfully!
echo [INFO] Check the logs with: kubectl logs -f -n %NAMESPACE% -l app=backend
goto :end

:cleanup
echo [INFO] Cleaning up existing deployment...
kubectl delete namespace %NAMESPACE% --ignore-not-found=true
echo [INFO] Waiting for namespace deletion...
kubectl wait --for=delete namespace/%NAMESPACE% --timeout=60s
echo [SUCCESS] Cleanup completed
exit /b 0

:end
endlocal