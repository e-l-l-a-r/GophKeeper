-- Откат миграции: сначала таблица записей, затем пользователи.
DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS users;
