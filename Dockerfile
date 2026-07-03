FROM python:3.12-slim AS base

WORKDIR /app

# Install system dependencies for weasyprint
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libffi-dev libcairo2 && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY rules/ rules/

# Install package
RUN pip install --no-cache-dir -e ".[pdf,crypto]"

# Default to scanning
ENTRYPOINT ["fgcheck"]
CMD ["--help"]
