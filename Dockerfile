FROM python:latest
LABEL maintainer="Brad Atkinson <brad.scripting@gmail.com>"

RUN mkdir /code

COPY ./config.py /code
COPY ./pan_threat_vault.py /code
COPY ./requirements.txt /code

RUN cd /code
RUN mkdir data/
RUN mkdir log/

#COPY ./data/vulnerability.json data/
#COPY ./data/phone-home.json data/

WORKDIR /code

RUN pip install -r requirements.txt

CMD ["python", "pan_threat_vault.py"]