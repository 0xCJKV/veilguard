#!/bin/bash

# Build the WASM package
echo "Building WASM package..."
wasm-pack build --target web --out-dir pkg --dev

# Copy index.html to pkg directory for serving
echo "Copying index.html..."
cp index.html pkg/

echo "Build complete! You can serve the frontend with:"
echo "cd pkg && python3 -m http.server 8000"
echo "Then open http://localhost:8000 in your browser"