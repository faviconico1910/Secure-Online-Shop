FROM python:3.10-slim

# Cài công cụ hệ thống
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    ninja-build \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Cài đặt liboqs từ branch main
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. && \
    ninja && \
    ninja install && \
    cd ../.. && rm -rf liboqs

# Configure lib path
RUN ldconfig

# Cài liboqs-python từ source mới nhất
RUN git clone --depth 1 --recursive https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
    python3 -m pip install . && \
    cd .. && rm -rf liboqs-python

# Xoá nếu còn bản pip sai
RUN pip uninstall -y oqs || true

# Tạo môi trường làm việc
WORKDIR /app

# Copy file và cài requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn
COPY . .

# Environment variables
ENV PYTHONPATH="${PYTHONPATH}:/app"
ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/usr/local/lib"

EXPOSE 5000

CMD ["python", "server.py"]
