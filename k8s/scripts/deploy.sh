#!/bin/bash

# Cybersecurity Platform Kubernetes Deployment Script
# This script builds and deploys the entire cybersecurity platform to Kubernetes

set -e

# Configuration
NAMESPACE="cybersecurity-platform"
REGISTRY_PREFIX="${REGISTRY_PREFIX:-cybersecurity}"
TAG="${TAG:-latest}"
ENVIRONMENT="${ENVIRONMENT:-development}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is not installed. Please install kubectl."
        exit 1
    fi
    
    # Check if kustomize is installed
    if ! command -v kustomize &> /dev/null; then
        print_warning "kustomize is not installed. Using kubectl apply -k instead."
    fi
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker."
        exit 1
    fi
    
    # Check if cluster is accessible
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Build Docker images
build_images() {
    print_info "Building Docker images..."
    
    local services=(
        "backend"
        "frontend" 
        "behavioral_analysis"
        "decoy_generator"
        "traffic_monitor"
        "threat_attribution"
        "visualization_dashboard"
        "threat_intelligence"
        "adaptive_deception"
        "evaluation_engine"
    )
    
    for service in "${services[@]}"; do
        print_info "Building $service..."
        
        local build_path="."
        local dockerfile="Dockerfile"
        
        # Handle different service paths
        case $service in
            "frontend")
                build_path="./frontend"
                ;;
            "evaluation_engine")
                build_path="./evaluation"
                ;;
            *)
                if [[ $service == "backend" ]]; then
                    build_path="./backend"
                else
                    build_path="./backend/${service}"
                fi
                ;;
        esac
        
        local image_name="${REGISTRY_PREFIX}-${service//_/-}:${TAG}"
        
        if [[ -f "${build_path}/${dockerfile}" ]]; then
            print_info "Building ${image_name} from ${build_path}"
            docker build -t "$image_name" "$build_path"
            print_success "Built $image_name"
        else
            print_warning "Dockerfile not found for $service at ${build_path}/${dockerfile}, skipping..."
        fi
    done
    
    print_success "All Docker images built successfully"
}

# Create namespace if it doesn't exist
create_namespace() {
    print_info "Creating namespace: $NAMESPACE"
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    print_success "Namespace $NAMESPACE ready"
}

# Deploy to Kubernetes
deploy_to_k8s() {
    print_info "Deploying to Kubernetes environment: $ENVIRONMENT"
    
    local overlay_path="./k8s/overlays/$ENVIRONMENT"
    
    if [[ ! -d "$overlay_path" ]]; then
        print_error "Environment overlay not found: $overlay_path"
        exit 1
    fi
    
    # Apply the manifests
    print_info "Applying Kubernetes manifests..."
    
    if command -v kustomize &> /dev/null; then
        kustomize build "$overlay_path" | kubectl apply -f -
    else
        kubectl apply -k "$overlay_path"
    fi
    
    print_success "Kubernetes manifests applied"
}

# Wait for deployments to be ready
wait_for_deployments() {
    print_info "Waiting for deployments to be ready..."
    
    local deployments=(
        "postgresql"
        "redis"
        "elasticsearch"
        "logstash"
        "kibana"
        "backend"
        "behavioral-analysis"
        "decoy-generator"
        "traffic-monitor"
        "threat-attribution"
        "visualization-dashboard"
        "threat-intelligence"
        "adaptive-deception"
        "evaluation-engine"
        "frontend"
    )
    
    for deployment in "${deployments[@]}"; do
        print_info "Waiting for $deployment..."
        
        # Different wait strategies for different resource types
        case $deployment in
            "postgresql")
                kubectl wait --for=condition=ready pod -l app=postgresql -n "$NAMESPACE" --timeout=300s
                ;;
            "elasticsearch")
                kubectl wait --for=condition=ready pod -l app=elasticsearch -n "$NAMESPACE" --timeout=300s
                ;;
            *)
                kubectl wait --for=condition=available deployment/"$deployment" -n "$NAMESPACE" --timeout=300s
                ;;
        esac
        
        if [[ $? -eq 0 ]]; then
            print_success "$deployment is ready"
        else
            print_error "$deployment failed to become ready"
        fi
    done
}

# Show deployment status
show_status() {
    print_info "Deployment Status:"
    echo
    
    print_info "Pods:"
    kubectl get pods -n "$NAMESPACE" -o wide
    echo
    
    print_info "Services:"
    kubectl get services -n "$NAMESPACE"
    echo
    
    print_info "Ingress:"
    kubectl get ingress -n "$NAMESPACE"
    echo
    
    # Get external access information
    local ingress_ip=$(kubectl get ingress cybersecurity-ingress -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)
    if [[ -z "$ingress_ip" ]]; then
        ingress_ip=$(kubectl get ingress cybersecurity-ingress -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null)
    fi
    
    if [[ -n "$ingress_ip" ]]; then
        print_success "Application is accessible at: http://$ingress_ip"
        print_info "Add this to your /etc/hosts file: $ingress_ip cybersecurity.local"
    else
        print_warning "Ingress IP not ready yet. Check 'kubectl get ingress -n $NAMESPACE' later."
        print_info "For local testing, you may need to use port-forward:"
        print_info "kubectl port-forward -n $NAMESPACE svc/frontend 3000:3000"
    fi
}

# Cleanup function
cleanup() {
    print_info "Cleaning up existing deployment..."
    kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
    print_info "Waiting for namespace deletion..."
    kubectl wait --for=delete namespace/"$NAMESPACE" --timeout=60s || true
    print_success "Cleanup completed"
}

# Main function
main() {
    print_info "Starting Cybersecurity Platform Kubernetes Deployment"
    print_info "Environment: $ENVIRONMENT"
    print_info "Namespace: $NAMESPACE"
    print_info "Registry Prefix: $REGISTRY_PREFIX"
    print_info "Tag: $TAG"
    echo
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cleanup)
                cleanup
                exit 0
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --environment=*)
                ENVIRONMENT="${1#*=}"
                shift
                ;;
            --tag=*)
                TAG="${1#*=}"
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --cleanup              Clean up existing deployment"
                echo "  --skip-build           Skip Docker image building"
                echo "  --environment=ENV      Set deployment environment (development|production)"
                echo "  --tag=TAG             Set Docker image tag"
                echo "  --help                Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Run deployment steps
    check_prerequisites
    
    if [[ "$SKIP_BUILD" != "true" ]]; then
        build_images
    else
        print_info "Skipping Docker image building"
    fi
    
    create_namespace
    deploy_to_k8s
    wait_for_deployments
    show_status
    
    print_success "Cybersecurity Platform deployed successfully!"
    print_info "Check the logs with: kubectl logs -f -n $NAMESPACE -l app=backend"
}

# Run main function
main "$@"