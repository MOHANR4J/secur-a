# Use official Puppeteer Docker image as the base
FROM ghcr.io/puppeteer/puppeteer:latest

# Set workspace directory
WORKDIR /app

# Copy package configuration files with user permissions
COPY --chown=pptruser:pptruser package*.json ./

# Install npm dependencies (production mode)
RUN npm ci --omit=dev

# Copy all application source files
COPY --chown=pptruser:pptruser . .

# Expose port (Render sets this dynamically, defaults to 5000)
EXPOSE 5000

# Start script
CMD [ "node", "server.js" ]
