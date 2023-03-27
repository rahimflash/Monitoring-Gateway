FROM python:3.8

COPY . /monitoring-gateway/
WORKDIR /monitoring-gateway/

RUN pip install -r requirements.txt
EXPOSE 5000

CMD ["python3", app.py]
