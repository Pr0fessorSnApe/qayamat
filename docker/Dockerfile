FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget ca-certificates chromium-driver golang-go \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies first (for layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install --with-deps chromium 2>/dev/null || true

# Copy application source
COPY . .

# Create runtime directories
RUN mkdir -p data reports logs /opt/qayamat/tools

# Add Go tools to PATH
ENV PATH="/root/go/bin:/opt/qayamat/tools:${PATH}"
ENV QAYAMAT_TOOLS=/opt/qayamat/tools

EXPOSE 8000

CMD ["python", "qayamat.py", "--dashboard-only"]
