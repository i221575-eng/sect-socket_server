# Use the official Python 3.10 image
FROM python:3.10

# Set the working directory in the container
WORKDIR /app

# Copy the application code to the working directory
COPY app/ .

# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your app runs on
EXPOSE 443

# Command to run the application
CMD [ "python", "server.py" ]
