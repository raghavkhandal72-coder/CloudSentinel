FROM python:3.11-slim

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Ensure no credentials are in the image (enforced via .dockerignore)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /app

USER appuser

# Simple healthcheck for a CLI container to prove it can run python
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python --version || exit 1

ENTRYPOINT ["python", "-m", "backend.main"]
CMD ["--mock"]
