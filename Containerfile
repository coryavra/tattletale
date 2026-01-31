FROM python:3.12-alpine
WORKDIR /app
COPY tattletale.py .
ENTRYPOINT ["python3", "tattletale.py"]
