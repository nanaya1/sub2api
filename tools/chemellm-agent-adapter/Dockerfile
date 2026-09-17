FROM python:3.12-alpine

WORKDIR /app
COPY adapter.py /app/adapter.py

RUN addgroup -S adapter && adduser -S -G adapter adapter
USER adapter

EXPOSE 18081
CMD ["python3", "/app/adapter.py"]
