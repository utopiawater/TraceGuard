FROM python:3.12-slim
WORKDIR /workspace
COPY pyproject.toml ./
COPY backend ./backend
COPY knowledge ./knowledge
RUN pip install --no-cache-dir .
ENV PYTHONPATH=/workspace/backend
ENV PYTHONUNBUFFERED=1
WORKDIR /workspace
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

