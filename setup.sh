#!/bin/bash

# PRIV-DEMI API Setup Script

echo "🚀 Setting up PRIV-DEMI API..."

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ Node.js 16 or higher is required"
    exit 1
fi

echo "✅ Node.js version: $(node -v)"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Create directories
echo "📁 Creating directories..."
mkdir -p logs storage/proxies storage/templates

# Generate API key if not exists
if [ ! -f .env ]; then
    echo "🔑 Generating API key..."
    API_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    
    cat > .env << EOF
# PRIV-DEMI API Configuration
NODE_ENV=development
PORT=3000
HOST=0.0.0.0
API_KEY=$API_KEY
ENABLE_AUTH=true
MAX_CONCURRENT_ATTACKS=50
MAX_ATTACK_DURATION=3600
MAX_ATTACK_THREADS=500
MAX_ATTACK_RATE=10000
WORKER_COUNT=$(nproc)
LOG_LEVEL=info
LOG_TO_FILE=true
LOG_DIR=./logs
PROXY_REFRESH_INTERVAL=300
MAX_PROXY_COUNT=10000
CORS_ORIGINS=*
EOF
    
    echo "✅ Generated .env file with API key: ${API_KEY:0:8}..."
fi

# Create initial proxy file
if [ ! -f proxies.txt ]; then
    echo "🌐 Creating initial proxy file..."
    echo "# Proxy list will be auto-populated" > proxies.txt
fi

# Make the original script executable
if [ -f "PRIV-DEMI-Original.js" ]; then
    chmod +x PRIV-DEMI-Original.js
fi

echo "🎉 Setup completed!"
echo ""
echo "📝 To start the API server:"
echo "   npm start"
echo ""
echo "🌐 Access the dashboard at:"
echo "   http://localhost:3000/dashboard"
echo ""
echo "🔑 Your API key is in the .env file"
echo "⚠️  Remember to secure your API key!"