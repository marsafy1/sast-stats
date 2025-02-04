import random
import requests

x = eval(input("Enter any python command"))
SECRET_KEY = "sdfjds;akfjsadkfljdsafkladshfjhjsadkfhdsa"
print(SECRET_KEY)
headers = {
    "X-Forwarded-For": f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
}
req = requests.post("whatever", {}, headers=headers)
print(headers)
