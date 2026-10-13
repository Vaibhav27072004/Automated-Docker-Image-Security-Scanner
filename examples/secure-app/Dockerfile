# ─────────────────────────────────────────────────────────────────────────────
# SECURE Dockerfile — Best Practices Applied
# This demonstrates the corrected, secure version after scanner remediation.
# ─────────────────────────────────────────────────────────────────────────────

# ✅ Fix 1: Pin the base image by DIGEST, not just by tag. A tag can be
#          repointed at new content; a digest cannot, so the build is
#          reproducible and cannot be swapped underneath you.
# ✅ Fix 2: Multi-stage build — builder stage for dependencies
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS builder

# Set working directory
WORKDIR /build

# ✅ Fix 3: Copy only what is needed for dependency installation (layer caching)
COPY requirements.txt .

# ✅ Fix 4: Pin pip and install with no-cache to reduce attack surface
RUN pip install --no-cache-dir --upgrade pip==24.0 \
    && pip install --no-cache-dir -r requirements.txt

# ─────────────────────────────────────────────────────────────────────────────
# Final production stage — minimal image
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

# ✅ Fix 5: Create a non-root user and group
RUN groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid appgroup --no-create-home appuser

WORKDIR /app

# ✅ Fix 6: Copy only the installed packages from builder (not the whole system)
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# ✅ Fix 7: Copy only application source (not the entire context)
COPY --chown=appuser:appgroup app.py .

# ✅ Fix 8: Switch to non-root user BEFORE final CMD
USER appuser

# ✅ Fix 9: Use an unprivileged port
EXPOSE 8080

# ✅ Fix 10: Add HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# ✅ Fix 11: Use exec form CMD (enables proper signal handling)
CMD ["python3", "app.py"]
