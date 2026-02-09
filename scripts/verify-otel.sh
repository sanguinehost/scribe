#!/bin/bash
set -e

# Configuration
JAEGER_IMAGE="docker.io/jaegertracing/all-in-one:latest"
OTLP_ENDPOINT="http://localhost:4317"
JAEGER_UI="http://localhost:16686"

echo "🚀 Starting OTLP Verification Process..."

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

# 2. Run the integration test
echo "🧪 Running OTel Verification Test..."
export OTEL_EXPORTER_OTLP_ENDPOINT=$OTLP_ENDPOINT
export OTEL_SERVICE_NAME="scribe-backend"

# Run with stdout exporter support if OTEL_STDOUT is set
if [ "$1" == "--stdout" ]; then
    export OTEL_STDOUT=1
    echo "📜 Using Stdout Exporter for immediate verification..."
fi

cargo test -p scribe-backend --test otel_verification --features otel -- --nocapture

echo ""
echo "✅ Verification test complete."
if [ -z "$OTEL_STDOUT" ]; then
    echo "📊 If Jaeger is running, you can view traces at: $JAEGER_UI"
fi
echo "Next steps for manual verification:"
echo "1. Open Jaeger UI: $JAEGER_UI"
echo "2. Select Service: 'scribe-backend'"
echo "3. Find 'verification_span'"
echo "4. Verify attributes 'user_id' and 'user_email' are REDACTED."
