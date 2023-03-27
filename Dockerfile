FROM python:3.8

# Copy source code to working directory
COPY . /monitoring-gateway/

# Create a working directory
WORKDIR /monitoring-gateway/

# Install packages from requirements.txt
# hadolint ignore=
RUN pip install --no-cache-dir --upgrade pip &&\
	pip install --no-cache-dir -r requirements.txt

# Expose port 80
EXPOSE 80

## Step 5:
# Run main.py at container launch
CMD [ "python3", "app.py"]
