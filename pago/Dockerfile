FROM python:3.12-slim
RUN groupadd -r dimed && useradd -r -g dimed -d /app -s /sbin/nologin dimed
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/uploads/comprobantes && chown -R dimed:dimed /app
USER dimed
EXPOSE 9000
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9000/health')" || exit 1
CMD ["gunicorn", "--bind", "0.0.0.0:9000", "--workers", "2", "--timeout", "120", "pago_app:app"]
