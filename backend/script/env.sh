#!/bin/bash

# env.sh - Copy .env.example to .env

set -e  # Exit on any error

# Function to find project root
find_project_root() {
    if [[ -f "Cargo.toml" ]]; then
        # We're in project root
        echo "."
    elif [[ -f "../Cargo.toml" ]]; then
        # We're in script directory
        echo ".."
    else
        echo "Error: Cannot find project root (no Cargo.toml found)" >&2
        exit 1
    fi
}

# Get project root directory
PROJECT_ROOT=$(find_project_root)

# Define file paths
ENV_EXAMPLE="$PROJECT_ROOT/.env.example"
ENV_FILE="$PROJECT_ROOT/.env"

# Check if .env.example exists
if [[ ! -f "$ENV_EXAMPLE" ]]; then
    echo "Error: .env.example not found at $ENV_EXAMPLE" >&2
    exit 1
fi

# Check if .env already exists
if [[ -f "$ENV_FILE" ]]; then
    echo "Warning: .env already exists at $ENV_FILE"
    read -p "Overwrite? (y/N): " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
fi

# Copy the file
cp "$ENV_EXAMPLE" "$ENV_FILE"
echo "✅ Copied .env.example to .env"
