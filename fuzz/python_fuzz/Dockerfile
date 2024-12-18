FROM python:3.10

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y nano ssh && apt-get clean

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["bash"]
