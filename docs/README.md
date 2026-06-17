# Документация

Тут лежит пользовательская инструкция и HTML-документация, которую генерирует
Doxygen.

Обычная команда сборки уже сама обновляет HTML:

```bash
cmake --build build
```

Если нужно пересобрать только документацию:

```bash
cmake --build build --target api-docs
```

Главная страница HTML находится в `docs/api/html/index.html`.
