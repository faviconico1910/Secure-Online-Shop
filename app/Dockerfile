FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    ninja-build \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs C library
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. && \
    ninja && \
    ninja install && \
    cd ../.. && \
    rm -rf liboqs

# Configure library path
RUN ldconfig

# Install liboqs-python from source
RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
    pip install . && \
    cd .. && \
    rm -rf liboqs-python

WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies (excluding liboqs-python which we built from source)
RUN pip install --no-cache-dir flask cryptography pycryptodome firebase-admin python-dotenv==1.0.0

# Copy application files
COPY . .

# Set environment variables
ENV PYTHONPATH="${PYTHONPATH}:/app"
ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/usr/local/lib"

EXPOSE 5000

CMD ["python", "server.py"]