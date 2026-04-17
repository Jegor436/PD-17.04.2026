import json
import hashlib
import secrets
import datetime
import os
import time

class User:
    def __init__(self, username, salt, password_hash, created_at=None, last_login=None, failed_attempts = 0, lockout_until = None):
        self.username = username
        self.salt = salt
        self.password_hash = password_hash
        self.created_at = created_at or datetime.datetime.now().isoformat()
        self.last_login = last_login
        self.failed_attempts = failed_attempts
        self.lockout_until = lockout_until

    def to_dict(self):
        return {
            "username": self.username,
            "salt": self.salt,
            "password_hash": self.password_hash,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "failed_attempts": self.failed_attempts,
            "lockout_until": self.lockout_until
        }
    
    @staticmethod
    def from_dict(data):
        return User(
            data["username"],
            data["salt"],
            data["password_hash"],
            data.get("created_at"),
            data.get("last_login"),
            data.get("failed_attempts", 0),
            data.get("lockout_until")
        )
    
class Storage:
    def __init__(self, filename="users.json"):
        self.filename = filename

    def load_users(self):
        if not os.path.exists(self.filename):
            return[]
        with open(self.filename, "r") as f:
            data = json.load(f)
            return [User.from_dict(u) for u in data]
        
    def save_users(self, users):
        with open(self.filename, "w") as f:
            json.dump([u.to_dict() for u in users], f, indent=4)

class AuthService:
    MAX_ATTEMPTS = 5
    LOCKOUT_SECONDS = 60

    def __init__(self, storage):
        self.storage = storage
        self.users = self.storage.load_users()

    def generate_salt(self):
        return secrets.token_hex(16)
    
    def hash_password(self, password, salt):
        return hashlib.sha256((salt + password).encode()).hexdigest()
    
    def find_user(self, username):
        for user in self.users:
            if user.username == username:
                return user
        return None
    
    def register(self, username, password):
        if self.find_user(username):
            print("Lietotājs jau eksistē.")
            return
        
        salt = self.generate_salt()
        password_hash = self.hash_password(password, salt)

        user = User(username, salt, password_hash)
        self.users.append(user)
        self.storage.save_users(self.users)

        print("Reģistrācija veiksmīga!")

    def login(self, username, password):
        user = self.find_user(username)

        if not user:
            self.log_attempt(username, "FAIL")
            print("Nepareizs lietotājvārds vai parole.")
            return None
        
        if user.lockout_until:
            now = datetime.datetime.now()
            lockout_time = datetime.datetime.fromisoformat(user.lockout_until)
            if now < lockout_time:
                sec_left = int((lockout_time - now).total_seconds())
                print(f"Lietotājs bloķēts vēl {sec_left} sekundes.")
                return None
            else:
                user.failed_attempts = 0
                user.lockout_until = None
        
        hashed_input = self.hash_password(password, user.salt)

        if hashed_input == user.password_hash:
            user.last_login = datetime.datetime.now().isoformat()
            user.failed_attempts = 0
            user.lockout_until = None
            self.storage.save_users(self.users)
            self.log_attempt(username, "SUCCESS")
            print("Pieslēgšanās veiksmīga!")
            return user
        else:
            user.failed_attempts += 1
            if user.failed_attempts >= self.MAX_ATTEMPTS:
                lockout_time = datetime.datetime.now() + datetime.timedelta(seconds=self.LOCKOUT_SECONDS)
                user.lockout_until = lockout_time.isoformat()
                print(f"Pārāk daudz nepareizu mēģinājumu. Lietotājs bloķēts uz {self.LOCKOUT_SECONDS} sekundēm.")
            else:
                print("Nepareizs lietotājvārds vai parole.")
            self.storage.save_users(self.users)
            self.log_attempt(username, "FAIL")
            return None

    def log_attempt(self, username, status):
        with open("auth.log", "a") as f:
            time_now = datetime.datetime.now().isoformat()
            f.write(f"{time_now} | {username} | {status}\n")

def main():
    storage = Storage()
    auth = AuthService(storage)

    while True:
        print("\n==== Mini Login System ====")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Izvēlies: ")

        if choice == "1":
            username = input("Username: ")
            password = input("Password: ")
            auth.register(username, password)

        elif choice == "2":
            username = input("Username: ")
            password = input("Password: ")
            user = auth.login(username, password)

            if user:
                while True:
                    print("\n1. Profile info")
                    print("2. Logout")
                    sub = input("Izvēlies: ")

                    if sub == "1":
                        print("\n--- Profils ---")
                        print("Username:", user.username)
                        print("Izveidots:", user.created_at)
                        print("Pēdējā pieslēgšanās:", user.last_login)
                    elif sub == "2":
                        break
                    else:
                        print("Nepareiza izvēle.")

        elif choice == "3":
            print("Programma beidzas.")
            break
        else:
            print("Nepareiza izvēle.")

if __name__ == "__main__":
    main()