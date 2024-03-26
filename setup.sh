#!/bin/bash

# Function to install PostgreSQL using apt-get
install_with_apt() {
    sudo apt-get update && sudo apt-get install -y postgresql postgresql-contrib
}

# Function to install PostgreSQL using yum
install_with_yum() {
    sudo yum update && sudo yum install -y postgresql-server postgresql-contrib
    # Initializing the database cluster (for RHEL/CentOS 7 and below)
    sudo postgresql-setup initdb
    # Enabling and starting the PostgreSQL service
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
}

# Function to install PostgreSQL using dnf
install_with_dnf() {
    sudo dnf install -y postgresql-server postgresql-contrib
    # Initializing the database cluster
    sudo postgresql-setup --initdb
    # Enabling and starting the PostgreSQL service
    sudo systemctl enable --now postgresql
}

# Check if psql command is available
if ! command -v psql > /dev/null; then
    # Detect the package manager and install PostgreSQL
    if command -v apt-get > /dev/null; then
        install_with_apt
    elif command -v dnf > /dev/null; then
        install_with_dnf
    elif command -v yum > /dev/null; then
        install_with_yum
    else
        echo "Package manager not supported. Please install PostgreSQL manually."
    fi
else
    echo "PostgreSQL is already installed."
fi

# Start PostgreSQL service
sudo service postgresql start

# Create a new database and user
sudo -u postgres psql -c "CREATE DATABASE mala;"

# Generate a random password and store in an env var
generate_password() {
    local PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)

    # Export the password as an environment variable
    export MALA_DB_PASS="$PASSWORD"
    echo "Password set in MALA_DB_PASS."
}
if [ -z "$MALA_DB_PASS" ]; then
    echo "MALA_DB_PASS is not set. Generating the env var now."
    generate_password
else
    echo "MALA_DB_PASS is set already, creating user if not existing with this value."
fi

sudo -u postgres psql -c "CREATE USER mala_user WITH ENCRYPTED PASSWORD '${MALA_DB_PASS}';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE mala TO mala_user;"
sudo -u postgres psql -d mala -c "GRANT ALL PRIVILEGES ON SCHEMA public TO mala_user;"
sudo -u postgres psql -d mala -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mala_user;"

echo "Finished mala setup."
