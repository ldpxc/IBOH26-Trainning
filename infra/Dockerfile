FROM python:3.12-slim

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/app.py .
# flag demo cho HT1 (không phải flag thật)
RUN echo "IBOH{demo_flag_ht1}" > /app/flag.txt

EXPOSE 8000
CMD ["python3", "app.py"]
