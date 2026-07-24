FROM python:3.10-slim

# Install system dependencies for Scapy, SQLite, and PyQt5 X11 display
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    sqlite3 \
    qtbase5-dev \
    qtchooser \
    qt5-qmake \
    qtbase5-dev-tools \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libfontconfig1 \
    libxrender1 \
    libxext6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default entrypoint runs NIDS dashboard
CMD ["python3", "dashboard.py"]
