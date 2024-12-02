FROM python:3.10
ENV PYTHONUNBUFFERED 1
RUN apt-get update 
RUN mkdir /app
WORKDIR /app
COPY . /app/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
# CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

