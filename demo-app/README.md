# vuln-api (demo)

A tiny, **deliberately vulnerable** Python service for testing the remediation
loop end to end. Never deploy it anywhere real.

- **Base layer:** `public.ecr.aws/docker/library/python:3.9-alpine3.16`. This is end-of-life Alpine with known CVEs. It comes from the ECR Public mirror of the official image, so CodeBuild avoids Docker Hub rate limits.
- **App layer:** `requirements.txt`. It pins old `cryptography`, `jinja2`, `requests`, `urllib3`, `idna` and `certifi`.

## Use it with the platform

- **Locally:** `python local_server.py` "pushes" this folder to a mock GitHub repo, then builds it, scans it and lets you Fix with AI and Push fix.
- **On AWS:** push this folder to its own GitHub repo; see the main README, "Deploy the loop to your AWS sandbox". Every push builds the image in CodeBuild, sends it to ECR, and Amazon Inspector scans it.

A fix moves `FROM` to `python:3.12-alpine` and bumps the pins. The re-scan then shows only a couple of MEDIUM findings in the new base image, and the gate is CLEAR.

## Build and run it by hand

```powershell
podman build -t localhost/demo/vuln-api:1.0 demo-app
podman run --rm -p 8000:8000 localhost/demo/vuln-api:1.0   # http://localhost:8000/health
```
