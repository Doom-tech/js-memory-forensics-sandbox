#pragma once

#include <string>

/**
 * @brief Декодирует строку base64 по RFC 4648 в строгом режиме.
 *
 * Функция используется для реализации безопасного helper-а `atob` внутри
 * V8-контекста. Пробельные ASCII-символы игнорируются, но padding проверяется
 * строго, чтобы битые строки не проходили незаметно.
 *
 * @param encoded Входная base64-строка.
 * @return Декодированные байты, сохранённые в std::string.
 *
 * @throws std::runtime_error если строка содержит недопустимый символ,
 *         неправильную длину или некорректный padding.
 */
std::string decodeBase64Strict(const std::string& encoded);
