#!/bin/bash

# E2E Test Runner Script
# This script runs the Playwright E2E tests

set -e

echo "=========================================="
echo "E2E Test Runner"
echo "=========================================="

# Check if backend is running
echo "Checking if backend is running on http://localhost:8000..."
if ! curl -s http://localhost:8000/health > /dev/null; then
    echo "ERROR: Backend is not running. Please start it with:"
    echo "  .venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000"
    exit 1
fi
echo "✓ Backend is running"

# Check if frontend is running
echo "Checking if frontend is running on http://localhost:5173..."
if ! curl -s http://localhost:5173 > /dev/null; then
    echo "ERROR: Frontend is not running. Please start it with:"
    echo "  cd frontend && npm run dev"
    exit 1
fi
echo "✓ Frontend is running"

# Run tests
echo ""
echo "Running E2E tests..."
echo "=========================================="

# Default: run all tests
TEST_ARGS="$@"

if [ -z "$TEST_ARGS" ]; then
    TEST_ARGS="tests/e2e/"
fi

.venv/bin/pytest $TEST_ARGS

echo ""
echo "=========================================="
echo "E2E tests completed"
echo "=========================================="
