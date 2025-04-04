# URL Shortener API Service

Этот репозиторий содержит API-сервис для сокращения ссылок, предоставляющий возможности создания коротких ссылок, редиректов, управления ссылками и аналитики переходов. Сервис поддерживает регистрацию пользователей и аутентификацию, что позволяет владельцам управлять только своими ссылками.

---

## Описание API

### Основной функционал

- **Сокращение ссылок:**  
  `POST /links/shorten` – принимает длинный URL, кастомный alias и время истечения. Возвращает сгенерированный короткий код.

- **Редирект по короткой ссылке:**  
  `GET /{short_code}` – перенаправляет пользователя на оригинальный URL.

- **Получение аналитики ссылки:**  
  `GET /links/{short_code}/stats` – возвращает дату создания, количество кликов, дату последнего доступа и срок действия.

- **Обновление ссылки:**  
  `PUT /links/{short_code}` – обновляет оригинальный URL (только для владельца).

- **Удаление ссылки:**  
  `DELETE /links/{short_code}` – удаляет ссылку (только для владельца).

- **Поиск по оригинальному URL:**  
  `GET /links/search?original_url={url}` – возвращает соответствующие короткие ссылки.

- **История истекших ссылок:**  
  `GET /links/expired` – возвращает список ссылок, у которых истёк срок действия.

- **Очистка ссылок:**  
  `DELETE /links/cleanup` – удаляет неиспользуемые или истекшие ссылки.

---

## Регистрация и аутентификация

### Регистрация

**Запрос:**  
`POST /register`

```json
{
  "username": "example_user",
  "password": "your_password"
}
```

### Логин

**Запрос:**  
`POST /login`  
Content-Type: `application/x-www-form-urlencoded`

```
username=example_user
password=your_password
```

**Ответ:**
```json
{
  "access_token": "your_jwt_token",
  "token_type": "bearer"
}
```

Аутентификация доступна через кнопку **Authorize** в Swagger UI.

---

## Примеры запросов

### Создание короткой ссылки

**Запрос:**  
`POST /links/shorten`  
```json
{
  "original_url": "https://www.example.com/very/long/url",
  "custom_alias": "myalias",
  "expires_at": "2025-04-01T12:00:00"
}
```

**Ответ:**
```json
{
  "short_code": "myalias",
  "original_url": "https://www.example.com/very/long/url"
}
```

---

### Редирект по короткой ссылке

**Запрос:**  
`GET /myalias`  
**Действие:** Перенаправление на `https://www.example.com/very/long/url`

---

### Получение статистики

**Запрос:**  
`GET /links/myalias/stats`

**Ответ:**
```json
{
  "original_url": "https://www.example.com/very/long/url",
  "created_at": "2025-03-30T14:00:00",
  "clicks": 15,
  "last_accessed_at": "2025-03-31T09:30:00",
  "expires_at": "2025-04-01T12:00:00"
}
```

---

### Обновление ссылки

**Запрос:**  
`PUT /links/myalias`  
```json
{
  "original_url": "https://www.example.com/new/url"
}
```

**Ответ:**
```json
{
  "message": "Ссылка обновлена",
  "short_code": "myalias"
}
```

---

### Удаление ссылки

**Запрос:**  
`DELETE /links/myalias`

**Ответ:**
```json
{
  "message": "Ссылка удалена"
}
```

---

### Поиск по оригинальному URL

**Запрос:**  
`GET /links/search?original_url=https://www.example.com/very/long/url`

**Ответ:** список найденных ссылок.

---

### Очистка ссылок

**Запрос:**  
`DELETE /links/cleanup`

**Ответ:**
```json
{
  "message": "Удалено X неиспользуемых или истекших ссылок"
}
```

---

## Инструкция по запуску


1. **Клонируйте репозиторий:**

2. **Создание базы PostgreSQL**
   Скачайте, установите PostgreSQL и создайте базу под наш проект.

3. **Настройка .env:**
   В файле .env необхидимо прописать логин, пароль и имя вашей базы.

4. **Запуск:**
```bash
docker-compose up --build
```

Доступно по адресу: http://localhost:8000  
Swagger UI: http://localhost:8000/docs

---


## Структура базы данных

### Таблица `users`

| Поле             | Описание                          |
|------------------|-----------------------------------|
| `id`             | Уникальный идентификатор          |
| `username`       | Уникальное имя пользователя       |
| `hashed_password`| Хэшированный пароль               |
| `links`          | Связь с таблицей ссылок           |

### Таблица `links`

| Поле              | Описание                               |
|-------------------|----------------------------------------|
| `id`              | Уникальный идентификатор               |
| `original_url`    | Оригинальный URL                       |
| `short_code`      | Уникальный alias                       |
| `created_at`      | Дата создания                          |
| `expires_at`      | Дата истечения (опционально)           |
| `last_accessed_at`| Последний доступ                       |
| `clicks`          | Счётчик переходов                      |
| `user_id`         | Внешний ключ на владельца (user)       |

---


## Запуск тестов

### Короткий отчет по тестам

```bash
python -m pytest tests
```

### Если интересует процент покрытия кода

```bash
python -m coverage run -m pytest tests
python -m coverage report
python -m coverage html
```

### Запуск тестов с нагрузкой

```bash
python -m locust -f locustfile.py
```
Тестирование происходит в веб интерфейсе по адресу

```bash
http://localhost:8089
```


В параметрах будет необходимо указать хост

```bash
http://localhost:8000
```
---

### Отчёт покрытия тестов
[Открыть HTML-отчёт](https://nekitur.github.io/apidz1/)
