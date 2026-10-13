FROM python:3.12-slim

# Install system dependencies including git (required for repository cloning)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configure git to be safe in all directories (needed for subprocess git calls)
RUN git config --global --add safe.directory '*'

WORKDIR /app

# Install python dependencies first (layer caching optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files (excluding files in .dockerignore)
COPY . .

# Ensure logs and data directories exist with correct permissions
RUN mkdir -p logs && chmod 755 logs

# Create a non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 7860

# HuggingFace Spaces uses port 7860 by default; Render uses PORT env var
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-7860} --workers 1"]
