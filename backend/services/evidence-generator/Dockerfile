FROM python:3.12-slim
WORKDIR /app
COPY services/evidence-generator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY services/evidence-generator /app/service
EXPOSE 8012
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8012"]
