FROM ghcr.io/zaproxy/zaproxy:stable
USER root
WORKDIR /app
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic pytest httpx kafka-python
COPY shared /app/shared
COPY services/zap-service /app/service
EXPOSE 8006
USER zap
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8006"]
