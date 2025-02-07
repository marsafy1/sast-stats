import re
import requests
import os
import base64

from test2 import get_const_mystrey, get_input_mystey
from http.client import HTTPException
from flask import Flask
from fastapi import FastAPI
from sqlalchemy import create_engine


def sanitize_input(user_input):
    return re.sub(r"[^a-zA-Z0-9_]", "", user_input)


#  Secrets expoded in a variable
SECRET_KEY = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"  #  Should be: (+)
GOOGLE_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvPIBZDANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPo8OxKW8JjeNT\nMMWuAAGcA9HBqTijz3hSk9cXRTVAm6zqawftXp7dO4zK/YrkyTd4fPtDTNoFw0b2\nIVAjxxkdAbnPTzBorzAXV74WDRFHpergQo8BqEVuQMIisbUH3qML5o13LhXIzAFM\nnM1hER6+WUDquXI1uYRR2LlkbFBXCVeb7AI7Gpu+Ge66vK3d9DnBTXRCIZhX9Yos\nz4l8AmcpWuT0v7oaXsjCDdiFPFnCR1InvP5KNLpeoKUUNPd3dlh6nkNYNmcnym1K\nENIxRwo16UCtlYkJRrKoWer87nmmast2OaulYVjqTcEzlLRTzXbhrZADtGNmGJd9\nnVSQWJl1AgMBAAECggEABlwbvay+i+peph5TpQq3AeepYGcl0aP51ChXFDgNyNbR\nKwpFieMLYUyro/lewbcwDcQLkM96dhFkdlwlhOhaP+Xc98PogFcCqr8Ilsr7q9gh\nzjtQ/1n/a8BsBygDms7E67O6GDEUgGakkODUoZPRVJSN7808+aGfCJVncvNRBU65\nJ3UN3lJAgO3qhdT4lkzNvPeSihSFbs82zJQPUW8vNAtZwCPH1mB373jdM/EjU7aN\ngEtHtx9pP0xFDOBU5mX+4P0VcUjb54vrD8u8N3wGmIWu7P7+w4EpbX+d4T+m0xPz\n7MNYj4VESTLuJMpX45S42QOZUHVgm0CgPgMio360QQKBgQDqT9rVupxjS/AimmaP\nspDNdUPLjecXwAfOSYmTxSs5vJFj2a2liWKHH+qfG/+mTAw2qeAm5idQ3c4PwS9o\npGlwtru5LB+uVaSdLpVQBPxcQPwGeKvYyZW7BcMIGzlPG+77zKa5Iviu7uOyPcS6\n61uab8NtqKFj14ZzEZqChBnxOQKBgQDi2+WkzVZTP0RPF3lDarjdZ6wyvQVBgf7f\nic5Y/7mX+GguRlJGSK2SU4+KazvxrJM0dwvba6VMa6D4p0Wbkc9FlqiAAfbxOTdr\nem9ZSsiWFLBsHNygM3UpzHT090cjj6fk/x0bze4WaQWlka4MjCkysMYLDXJBtVqE\nf/xGnfh2HQKBgFYlW+CehmbfgX9HYxPL4/8V8QICvwb1XClU0hcZM6Y7lPywCG7H\nDwl9C4bKBXj/lrH2TOogTi4mDl+ueB6x6+470NLozREMfcQoX08XNi042zAJ56yB\nmOI04Rq236AdNgUvndCNcf7m56IdoZnTdE9YbfKAQC30DIN74mG/7cXJAoGAT2d+\nkteYfpzncPOba0CAomZ2PHAy1cIFjwKyKi6gLJQzCvdsNtObhVsgI+fy3F12TOfa\nS5v7CKundUE/OPupXAcmxV9qqvZG8qSxMsTdPsLRGZZkluJMASxiR5gB222d66Zr\n7t5+lnN+GXzLOfMZPHfpadb0BhHPNA+EIseKPvUCgYEAid/dY8w6IRzNKWNQGlob\nEqCGDv7Fx77lHAUysJd7lYD9DD4nFOjes2IN6eQA9uc1BQP1B60+ZV9pwVa9nYmu\nJ89vSgqRSRlvN/zqILMkah4oAFaHOf7Uxjxr9jDK+vo7NHteg/JoVRVpu6M2NiWE\nnQq5VN2Rk5RZEkDxXetb8hQ=\n-----END PRIVATE KEY-----"  #  Should be: (+)

# Commented Secret
# SECRET_KEY = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0" # Should be: (+)


# Inputs
user_input = input("Write a python code...\n")

# CONSTANT from imported function
eval(get_const_mystrey())  # Should be: (-)

# User input from imported function
eval(get_input_mystey())  # Should be: (+)

# Dangerous eval but commented out
# eval(input()) # Should be: (-)

# eval with user input
eval(user_input)  # Should be: (+)

# eval with checker (if condition/assert)
if user_input.isdigit:
    eval(user_input)  # Should be: (-)

assert user_input.isdigit
eval(user_input)  # Should be: (-)


# eval with sanitazied input
eval(sanitize_input(user_input))  # Should be: (-)

# eval with constant string
eval("5 + 5")  # Should be: (-)

# eval with constant f format
eval(f"{user_input}")  # Should be: (+)

# eval with user input
eval("mys".replace("mys", user_input))  # Should be: (+)


# eval with user input even if marked as string
eval(str(user_input))  # Should be: (+)

# eval with user
eval("input()")  # Should be: (-)

# eval with user input
eval("eval(input())")  # Should be: (+) < Good one
eval("EvAl(input())".lower())  # Should be: (+) < Good one
eval("base64.b64decode('ZXZhbChpbnB1dCgpKQ==')")  # Should be: (+) < Good one+1

# overwritten the variable
user_input = "5*5"
eval(user_input)  # Should be: (-)


# SQL
import sqlite3

conn = sqlite3.connect("TMP.db")
cursor = conn.cursor()
noway = input()
cursor.execute(f"SELECT * FROM USERS WHERE username = {noway};")  # Should be: (+)


noway = "5*5"
cursor.execute(f"SELECT * FROM USERS WHERE username = {noway};")  # Should be: (-)


# Eval
eval(input())  # Should be (+)


# Eval from request headers
response = requests.get("https://api.example.com/data")
eval(response.headers.get("Content-Type"))  # Should be (+)


# Mini flask app
def application1():
    app = Flask(__name__)
    app.secret_key = "ABCDEFG"  # Should be (+)
    app.run()


# FastAPI
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL)

app = FastAPI()


# SQL injection
@app.get("/users/{user_id}")
def read_user(user_id: str):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"  # Shoud be (+)
    with engine.connect() as connection:
        result = connection.execute(query)
        user = result.fetchone()
    return user


# RCE
@app.post("/execute/")
def execute_command(command: str):
    exec(command)  # Vulnerable to RCE
    return {"message": "Executed"}  # Shoud be (+)


# Path Traversal
BASE_DIR = "/safe/base/dir"


@app.get("/files/{filename}")
def read_file(filename: str):
    file_path = os.path.join(BASE_DIR, filename)  # Shoud be (+)
    with open(file_path, "r") as f:
        return {"content": f.read()}


@app.get("/files/{filename}")
def read_safe_file(filename: str):
    safe_path = os.path.join(BASE_DIR, filename)
    # Prevent directory traversal
    if not safe_path.startswith(BASE_DIR):
        raise HTTPException(status_code=403, detail="Forbidden path")

    if not os.path.exists(safe_path):
        raise HTTPException(status_code=404, detail="File not found")

    with open(safe_path, "r") as f:
        return {"content": f.read()}


"""


                >>>>>> Repaeted the code above 4 times to measure speed <<<<<<


"""
