#pragma once

#include "analysis_types.hpp"

#include <memory>
#include <string>
#include <vector>

/**
 * @brief RAII-обёртка для глобальной инициализации V8 в процессе.
 *
 * Объект нужно создать до создания экземпляров JsSandbox и держать живым до
 * тех пор, пока все песочницы не будут уничтожены. Так жизненный цикл V8
 * остаётся явным и не размазывается по коду.
 */
class V8Runtime {
public:
    /**
     * @brief Инициализирует V8 и задаёт лимит old-space heap.
     *
     * @param executablePath Путь к текущему исполняемому файлу. V8 использует
     *        его для поиска ICU и startup data, если это требуется сборкой.
     * @param maxOldSpaceMb Максимальный размер old-space heap в мегабайтах.
     *
     * @throws std::runtime_error если проект собран без поддержки V8 или лимит
     *         памяти задан некорректно.
     */
    V8Runtime(const char* executablePath, int maxOldSpaceMb);

    /**
     * @brief Завершает работу платформенной части V8, принадлежащей процессу.
     */
    ~V8Runtime();

    V8Runtime(const V8Runtime&) = delete;
    V8Runtime& operator=(const V8Runtime&) = delete;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Ограниченный исполнитель JavaScript для форензического анализа памяти.
 *
 * Песочница создаёт отдельный V8 isolate и пустой context. В глобальный объект
 * добавляются только небольшие helper-функции: `print`, `mark` и `atob`.
 * Node.js API, файловая система, сеть и объект process в контекст не добавляются.
 */
class JsSandbox {
public:
    /**
     * @brief Создаёт изолированный JavaScript-контекст.
     *
     * @param config Таймаут выполнения и лимит V8 heap.
     *
     * @throws std::runtime_error если V8 недоступен или параметры лимитов
     *         некорректны.
     */
    explicit JsSandbox(SandboxConfig config);

    /**
     * @brief Освобождает context, isolate и закреплённые JS-значения.
     */
    ~JsSandbox();

    JsSandbox(const JsSandbox&) = delete;
    JsSandbox& operator=(const JsSandbox&) = delete;

    /**
     * @brief Компилирует и запускает JavaScript-файл внутри песочницы.
     *
     * @param scriptPath Путь к входному JavaScript-файлу.
     * @return Статус выполнения, флаг таймаута и диагностическое сообщение.
     *
     * @throws std::runtime_error если файл нельзя прочитать или V8 не может
     *         создать строку исходного кода.
     */
    ScriptResult executeFile(const std::string& scriptPath);

    /**
     * @brief Сохраняет текущий граф V8 heap в JSON-файл.
     *
     * @param path Путь к выходному файлу heap snapshot.
     *
     * @throws std::runtime_error если snapshot нельзя создать или записать.
     */
    void writeHeapSnapshot(const std::string& path);

    /**
     * @brief Возвращает значения, закреплённые через mark(name, value).
     *
     * @return Неизменяемый список значений, которые скрипт передал в mark().
     */
    const std::vector<TrackedValue>& trackedValues() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
