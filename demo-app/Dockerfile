# Deliberately old base image (EOL Alpine 3.16), from the ECR Public mirror of the
# official image (no Docker Hub rate limits in CodeBuild). The platform moves it to a fixed tag.
FROM public.ecr.aws/docker/library/python:3.12-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

EXPOSE 8000
USER nobody
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '8000'), timeout=4)" || exit 1
CMD ["python", "app.py"]
