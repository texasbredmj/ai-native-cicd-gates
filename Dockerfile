FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml requirements.lock ./
COPY src ./src
RUN pip install --no-cache-dir -r requirements.lock . && useradd --create-home gates
USER gates
WORKDIR /home/gates
ENTRYPOINT ["ai-gates"]
