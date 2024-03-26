#!/bin/bash

# Install PostgreSQL if it's not already installed
if ! command -v psql > /dev/null; then
    sudo apt-get update && sudo apt-get install -y postgresql postgresql-contrib
fi

# Start PostgreSQL service
sudo service postgresql start

# Create a new database and user
sudo -u postgres psql -c "CREATE DATABASE mala;"
sudo -u postgres psql -c "CREATE USER mala_user WITH ENCRYPTED PASSWORD 'pass';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE mala TO mala_user;"
sudo -u postgres psql -d mala -c "GRANT ALL PRIVILEGES ON SCHEMA public TO mala_user;"
sudo -u postgres psql -d mala -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mala_user;"
