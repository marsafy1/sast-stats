import random
import requests

x = eval(input("Enter any python command"))
SECRET_KEY = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"
print(SECRET_KEY)
headers = {
    "X-Forwarded-For": f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
}
req = requests.post("whatever", {}, headers=headers)
print(headers)
