FROM quay.io/centos/centos:stream8

RUN dnf install -y glibc-langpack-en python3.11 make openssl

# Create and activate virtual environment
RUN python3.11 -m venv /venv
ENV PATH="/venv/bin:$PATH"
ENV VAULT_TOKEN="B38woSMKwOIJjcwg4mHGmtBDTUJ7ikWe0kCGVnxoJNWnwTyEyE1vckS2CuYbdK9S"
ENV VAULT_URL="https://localhost:8200"
ENV VAULT_ADDR="https://localhost:8200"

# Install Twine in Python
RUN python3.11 -m pip install build twine pytest pyarrow requests

# Set virtual environment as entrypoint
ENTRYPOINT ["/bin/bash"]
