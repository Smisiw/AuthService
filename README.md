# AuthService

Микросервис аутентификации и авторизации пользователей. Реализует регистрацию, вход по паролю, выдачу JWT-токенов, ротацию refresh-токенов и выход из системы.

- **Порт:** 8081
- **Имя в Eureka:** `AUTH-SERVICE`
- **Java:** 21
- **Spring Boot:** 3.4.4

---

## Содержание

- [Назначение](#назначение)
- [API эндпоинты](#api-эндпоинты)
- [Модель данных](#модель-данных)
- [Переменные окружения](#переменные-окружения)
- [Сборка и запуск](#сборка-и-запуск)
- [Тесты](#тесты)

---

## Назначение

AuthService выполняет следующие функции:
- Регистрация новых пользователей с хешированием паролей (BCrypt).
- Аутентификация по email + пароль; при успехе возвращает пару `token` (access) + `refresh_token`.
- Обновление access-токена по действующему refresh-токену.
- Выход из системы с инвалидацией refresh-токена.

JWT подписывается алгоритмом HMAC-SHA с ключом из `JWT_SECRET`. Тот же секрет используется всеми остальными сервисами для самостоятельной проверки токенов без обращения к AuthService.

---

## API эндпоинты

Все маршруты AuthService доступны через API Gateway по адресу `http://localhost:8080/auth/**`.
Маршрут `/auth/**` публичный — Gateway не проверяет JWT для этих запросов.

| Метод | Путь              | Тело запроса                          | Ответ                                   | Описание                                |
|-------|-------------------|---------------------------------------|------------------------------------------|-----------------------------------------|
| POST  | `/auth/register`  | `{"email":"...","password":"..."}`    | `200 "User registered successfully"`     | Регистрация; роль `ROLE_USER` по умолчанию |
| POST  | `/auth/login`     | `{"email":"...","password":"..."}`    | `200 {"token":"...","refresh_token":"..."}` | Вход; возвращает пару токенов           |
| POST  | `/auth/refresh`   | `{"refreshToken":"..."}`              | `200 {"token":"...","refresh_token":"..."}` | Ротация токенов                         |
| POST  | `/auth/logout`    | `{"refreshToken":"..."}`              | `200 "Logged out successfully"`          | Инвалидация refresh-токена              |

### Примеры

**Регистрация:**
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'
```

**Вход:**
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'
```

**Обновление токена:**
```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<ваш-refresh-token>"}'
```

---

## Модель данных

**Таблица `users`:**

| Поле       | Тип     | Ограничения         |
|------------|---------|---------------------|
| `id`       | UUID    | PK, генерируется    |
| `email`    | VARCHAR | NOT NULL, UNIQUE    |
| `password` | VARCHAR | NOT NULL (bcrypt)   |

**Таблица `user_roles`:** связующая таблица `user_id` ↔ `role_id`.

**Таблица `roles`:** содержит записи `ROLE_USER`, `ROLE_SELLER`, `ROLE_ADMIN`.

**Refresh-токены** хранятся в отдельной таблице и привязаны к пользователю. TTL задаётся переменной `JWT_REFRESH_EXPIRATION`.

Схема управляется Flyway (`classpath:db/migration`).

---

## Переменные окружения

| Переменная               | По умолчанию (dev)                                 | Описание                          |
|--------------------------|----------------------------------------------------|-----------------------------------|
| `DB_URL`                 | `jdbc:postgresql://localhost:5433/auth_db`         | JDBC-URL PostgreSQL               |
| `DB_USERNAME`            | `user`                                             | Пользователь БД                   |
| `DB_PASSWORD`            | `password`                                         | Пароль БД                         |
| `JWT_SECRET`             | `nTDmGYqtvLfDCptgzwG+xKGtXV/JHL4fHKJrxK9tHdI=`   | HMAC-ключ подписи JWT             |
| `JWT_EXPIRATION`         | `86400000`                                         | TTL access-токена, мс (24 часа)   |
| `JWT_REFRESH_EXPIRATION` | `604800000`                                        | TTL refresh-токена, мс (7 дней)   |
| `EUREKA_URL`             | `http://localhost:8761/eureka/`                    | Адрес Eureka Discovery            |

---

## Сборка и запуск

### Через Docker Compose (рекомендуется)

```bash
cd MarketPlaceProject
docker compose -f docker-compose.dev.yml up --build auth-service auth-db -d
```

### Локально из исходников

Требования: JDK 21, PostgreSQL 15 с базой `auth_db`.

```bash
cd AuthService
./gradlew bootRun
```

С переопределением параметров:
```bash
DB_URL=jdbc:postgresql://localhost:5433/auth_db \
DB_PASSWORD=mypassword \
JWT_SECRET=my-secret-key \
./gradlew bootRun
```

### Сборка JAR

```bash
cd AuthService
./gradlew build
# JAR: build/libs/auth_service-0.0.1-SNAPSHOT.jar
```

---

## Тесты

```bash
cd AuthService
./gradlew test
```

Тестовые классы находятся в `src/test/java/ru/projects/auth_service/`:
- `service/AuthServiceTest.java` — тесты логики аутентификации
- `service/RefreshTokenServiceTest.java` — тесты управления refresh-токенами

Health-check endpoint: `GET http://localhost:8081/actuator/health`
