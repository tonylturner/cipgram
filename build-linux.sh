#!/bin/bash
# Build CIPgram for Linux using Docker

echo "🏗️  Building CIPgram for Linux..."

# Build the Docker image and extract the binary
docker build -f Dockerfile.build -t cipgram-builder .

# Create a temporary container to extract the binary
docker create --name cipgram-temp cipgram-builder

# Extract the binary
docker cp cipgram-temp:/usr/local/bin/cipgram ./cipgram-linux

# Clean up
docker rm cipgram-temp

echo "✅ Linux binary created: cipgram-linux"
ls -lh cipgram-linux

echo ""
echo "To use on Linux:"
echo "  scp cipgram-linux user@linux-server:/tmp/"
echo "  ssh user@linux-server 'sudo mv /tmp/cipgram-linux /usr/local/bin/cipgram && sudo chmod +x /usr/local/bin/cipgram'"

