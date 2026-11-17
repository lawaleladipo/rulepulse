FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd -r rulepulse && useradd -r -g rulepulse rulepulse

COPY requirements.txt setup.py README.md ./
COPY src/ ./src/
COPY sample_data/ ./sample_data/

RUN pip install --no-cache-dir -e . && chown -R rulepulse:rulepulse /app

USER rulepulse

ENTRYPOINT ["rulepulse"]
CMD ["audit", "--sample"]
