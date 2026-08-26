# syntax=docker/dockerfile:1

FROM python:3.8-slim-buster

COPY tmp dir

RUN pip3 install pipreqs
RUN pipreqs dir
RUN pip3 install -r dir/requirements.txt

CMD ["python3", "dir/CVE-2019-16113.py"]
