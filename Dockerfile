FROM python:3.11.4-alpine3.18 AS python

RUN apk --no-cache add curl htop sqlite net-tools
RUN mkdir /app
WORKDIR /app

COPY . /app
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 6514/udp
ENV APP_HOST=0.0.0.0
CMD ["python", "/app/log_parser.py"]
