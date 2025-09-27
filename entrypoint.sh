#!/bin/sh

# Create data directories if they don't exist
mkdir -p /app/data/plots
mkdir -p /app/data/submissions
mkdir -p /app/data/injects
mkdir -p /app/data/temporary
mkdir -p /app/data/scoredfiles
mkdir -p /app/data/keys
mkdir -p /app/data/submissions/pcrs

# Fix ownership of data directories
chown -R quotient:quotient /app/data

# Switch to quotient user and run the application
exec su-exec quotient "$@"
