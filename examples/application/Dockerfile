FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /application
COPY app.py settings.json ./
USER 65534:65534
ENTRYPOINT ["python", "app.py"]
