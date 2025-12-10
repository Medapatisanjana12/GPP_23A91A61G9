# =========================================================
# Stage 1: Builder
# =========================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Copy only dependency file for caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["python","appy.py"]
