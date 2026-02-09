#!/bin/bash
set -e

# Configuration
JAEGER_IMAGE="docker.io/jaegertracing/all-in-one:latest"
OTLP_ENDPOINT="http://localhost:4317"
JAEGER_UI="http://localhost:16686"

echo "🚀 Starting EDM Lifecycle & Scaling Verification..."

# 1. Start Jaeger if not running
if [ ! "$(podman ps -q -f name=jaeger)" ]; then
    if [ "$(podman ps -aq -f status=exited -f name=jaeger)" ]; then
        echo "🔄 Restarting existing Jaeger container..."
        podman start jaeger
    else
        echo "🐳 Starting new Jaeger container (using podman)..."
        podman run -d --name jaeger \
            -e COLLECTOR_OTLP_ENABLED=true \
            -p 16686:16686 \
            -p 4317:4317 \
            -p 4318:4318 \
            $JAEGER_IMAGE
    fi
else
    echo "✅ Jaeger is already running."
fi

echo "⏳ Waiting for Jaeger to be ready..."
sleep 2

# 2. Run the EDM Scaling integration test
echo "🧪 Running EDM Scaling & Concurrency Test..."
export OTEL_EXPORTER_OTLP_ENDPOINT=$OTLP_ENDPOINT
export OTEL_SERVICE_NAME="scribe-edm-worker"

# We run with desktop features for SQLite scaling test
cargo test -p scribe-backend --test edm_scaling --no-default-features --features desktop -- --nocapture

echo ""
echo "✅ EDM Scaling Verification complete."
echo "📊 View traces at: $JAEGER_UI"
echo ""
echo "Distributed Scaling Validation Checklist:"
echo "1. Trace Continuity: Verify 'scaling_workflow' spans show parent-child links across workers."
echo "2. Atomicity: Confirmed 50 tasks processed by 5 concurrent workers without double-claims."
echo "3. Durability: SQLite immediate transactions proved safe for single-binary concurrency."
