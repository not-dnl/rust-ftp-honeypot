import time

def lock_one():
    start_time = time.time()
    while True:
        elapsed_time = time.time() - start_time
        if elapsed_time > 10:  # Lock expires after 10 seconds
            return False
        password = input("Enter password to unlock: ")
        if password == "OpenSesame":
            return True
        else:
            print("Incorrect password. Try again.")

def calculate_sum():
    if lock_one():
        result = 1 + 2
        print("Sum of 1 and 2 is:", result)
    else:
        print("Sorry, the lock couldn't be opened.")

calculate_sum()