FROM python:3.12-slim
WORKDIR /app
COPY services/agent-mesh/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY services/agent-mesh /app/service
EXPOSE 8013
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8013"]
