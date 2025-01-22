import psycopg2
import subprocess

DB_HOST = "127.0.0.1"
DB_NAME = "blocked_ip_db"
DB_USER = "postgres"
DB_PASSWORD = "postgres"

BLACKLIST_FILE="../database/blacklist.txt"

import os

def add_ips_to_database(conn, cursor):
    print("\nInitializing database...")

    try:
        print("Updating blacklist from remote source...")

        subprocess.run("curl https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v '#' | cut -f 1 > ../database/blacklist-new.txt", shell=True, check=True)

        print("Blacklist updated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating blacklist: {e}")
        return

    try:
        cursor.execute("SELECT COUNT(*) FROM blocked_ips")
        count = cursor.fetchone()[0]
        print(f"\nNumber of IP in database before update: {count}")

        old_ips = set()
        new_ips = set()

        if os.path.exists(BLACKLIST_FILE):
            with open(BLACKLIST_FILE, "r") as f:
                for line in f:
                    ip = line.strip()
                    old_ips.add(ip)

        with open("../database/blacklist-new.txt", "r") as f:
            for line in f:
                ip = line.strip()
                new_ips.add(ip)

        new_ips_to_add = new_ips - old_ips
        print(f"Found {len(new_ips_to_add)} new IP addresses to add to the database.")

        for ip in new_ips_to_add:
            cursor.execute("INSERT INTO blocked_ips (ip) VALUES (%s) ON CONFLICT (ip) DO NOTHING", (ip,))
        conn.commit()

        print("\nDatabase was initialized")
        cursor.execute("SELECT COUNT(*) FROM blocked_ips")
        count = cursor.fetchone()[0]
        
        if new_ips_to_add != 0:
            print(f"Number of IP in database after update: {count}")

        os.remove(BLACKLIST_FILE)
        os.rename("../database/blacklist-new.txt", BLACKLIST_FILE)

    except FileNotFoundError:
        print(f"Error: Blacklist file not found at {BLACKLIST_FILE}")
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        conn.rollback()



def connect_to_db():
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
        cursor = conn.cursor()
        
        print("Connected to DataBase")
        
        return conn, cursor
    except psycopg2.Error as e:
    
        print(f"Ошибка подключения к базе данных: {e}")
        
        return None, None

def is_ip_blocked(cursor, ip):
    try:
        cursor.execute("SELECT 1 FROM blocked_ips WHERE ip = %s", (ip,))
        
        return cursor.fetchone() is not None
        
    except psycopg2.Error as e:
    
        print(f"Database error: {e}")
        
        return False

def close_db_connection(conn):
    if conn:
        conn.close()
