import sqlite3
import os
import pickle
import subprocess

def login(username, password):
    # SQL Injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def run_backup(path):
    # Command injection with shell=True
    subprocess.Popen(f"tar czf backup.tar.gz {path}", shell=True)

def load_session(data):
    # Insecure deserialization
    return pickle.loads(data)
