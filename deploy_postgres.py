import subprocess
import os
import secrets
import time
import getpass

def check_postgres():
    try:
        subprocess.run(["pg_isready"], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def deploy_postgres():
    if check_postgres():
        print("PostgreSQL is already running locally.")
        return
    
    db_name = "ssl_database"
    db_user = "ssl_user"
    db_password = getpass.getpass("Enter password for PostgreSQL database: ")

    # Set environment variables for the script
    os.environ["POSTGRES_USER"] = db_user
    os.environ["POSTGRES_PASSWORD"] = db_password
    os.environ["POSTGRES_DB"] = db_name

    print("PostgreSQL is not running locally. Deploying with Docker...")

    try:
        # Pull the PostgreSQL image
        subprocess.run(["docker", "pull", "postgres:latest"], check=True, capture_output=True)

        # Run the container
        container_name = "ssl_postgres"
        subprocess.run([
            "docker", "run", "-d", "-p", "5432:5432",
            "-e", f"POSTGRES_DB={db_name}",
            "-e", f"POSTGRES_USER={db_user}",
            "-e", f"POSTGRES_PASSWORD={db_password}",
            "--name", container_name,
            "postgres:latest"
        ], check=True, capture_output=True)

        print(f"PostgreSQL container '{container_name}' started.")

        # Wait for the database to be ready
        print("Waiting for database to become available...")
        time.sleep(10)  # Initial wait

        max_attempts = 10
        for attempt in range(max_attempts):
            if check_postgres():
                print("Database is ready.")
                break
            else:
                print(f"Attempt {attempt + 1}/{max_attempts}: Not ready yet. Waiting...")
                time.sleep(5)
        else:
            raise Exception("Database did not become ready in time.")


        # Initialize the database schema
        init_script = "init_ssl_db.sql"
        if os.path.exists(init_script):
            print("Initializing database schema...")
            subprocess.run([
                "docker", "exec", container_name,
                "psql", f"postgresql://{db_user}:{db_password}@{container_name}/{db_name}", "-f", init_script
            ], check=True)
            print("Database schema initialized.")
        else:
            print(f"Initialization script '{init_script}' not found. Skipping schema initialization.")

        print("\nDatabase Credentials:")
        print(f"  Host: localhost")
        print(f"  Port: 5432")
        print(f"  Database: {db_name}")
        print(f"  User: {db_user}")
        print(f"  Password: {db_password}")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        if e.stderr:
            print(e.stderr.decode())
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    deploy_postgres()