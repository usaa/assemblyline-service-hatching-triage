ARG branch=stable
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH hatching.Hatching

USER assemblyline

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy service code
WORKDIR /opt/al_service
COPY hatching hatching
COPY service_manifest.yml .

# Patch version in manifest
ARG version=4.5.0.dev0
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
