# Base node image
FROM python:3.11.4-alpine3.18 AS python
#FROM python:3.11.4-bullseye AS python

# Install curl for health check
RUN apk --no-cache add curl htop
RUN mkdir /app
WORKDIR /app


COPY . /app
# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt


# Node API setup
EXPOSE 6514/udp 5080/tcp
#ENV HOST=0.0.0.0
CMD ["python", "/app/log_parser.py"]
#CMD ["/bin/sh"]
