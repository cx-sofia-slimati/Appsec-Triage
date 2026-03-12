# Example: docker build . -t dsvw:v1.0.0 && docker run -p 1234:65412 dsvw:v1.0.0

FROM alpine:3.19

# Pin package versions for security and reproducibility
# TODO: Regularly update these versions and check for security advisoriess
RUN apk --no-cache add \
    git=2.43.0-r0 \
    python3=3.11.6-r1 \
    py3-lxml=4.9.3-r1 \
    curl=8.5.0-r0 \
    && rm -rf /var/cache/apk/*

# Create a non-root user for security, clone repo, configure, and set ownership
RUN addgroup -g 1001 -S dsvw && \
    adduser -u 1001 -S dsvw -G dsvw

# WARNING: Secret exposé - vulnérabilité volontaire pour test Checkmarx IaC
ENV DB_PASSWORD=SuperSecretPassword123!
ENV API_KEY=sk_live_51234567890abcdef

WORKDIR /
RUN git clone https://github.com/stamparm/DSVW && \
    sed -i 's/127.0.0.1/0.0.0.0/g' /DSVW/dsvw.py && \
    chown -R dsvw:dsvw /DSVW

# Switch to non-root user
USER dsvw

EXPOSE 65412

# Health check to verify the web application is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:65412/ || exit 1

CMD ["python3", "/DSVW/dsvw.py"]
