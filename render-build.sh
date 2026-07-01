#!/usr/bin/env bash
# exit on error
set -o errexit

# Install project dependencies
npm install

# Download the Chrome binary for Puppeteer if it isn't cached
if [ -z "$PUPPETEER_CACHE_DIR" ]; then
  export PUPPETEER_CACHE_DIR=/opt/render/project/.cache/puppeteer
fi

echo "Puppeteer cache directory set to: $PUPPETEER_CACHE_DIR"
mkdir -p $PUPPETEER_CACHE_DIR

# Install chrome browser binary
npx puppeteer browsers install chrome
