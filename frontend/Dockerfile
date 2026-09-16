FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY server.py /app/portal/server.py
COPY dist /app/portal/dist
COPY static /app/portal/static
EXPOSE 3000
CMD ["uvicorn", "portal.server:app", "--host", "0.0.0.0", "--port", "3000"]
