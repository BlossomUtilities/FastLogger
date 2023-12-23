#pragma once

#ifndef FASTLOGGER_1_LOGGER_HPP
#define FASTLOGGER_1_LOGGER_HPP

#include <iostream>
#include <string>
#include <ctime>
#include <stdexcept>

#ifdef _WIN32
#include <Windows.h>
#include <chrono>
#undef ERROR
#endif

#define FASTLOGGER_LOGGING_FUNCTION(name, level, requiresDebugging) \
    void name(const std::string& message) {                         \
        if (requiresDebugging && !debuggingEnabled) return;         \
                                                                    \
        println(message, LogLevel::level);                          \
    }                                                               \

namespace Blossom::Logging {
    enum class LogLevel {
        TRACE,
        DEBUG,
        INFO,
        NOTICE,
        WARNING,
        ERROR,
        CRITICAL,
        CRASH
    };

    class Logger {
    private:
        static std::string logLevelToString(LogLevel level) {
            switch (level) {
                case LogLevel::TRACE:    return "TRACE";
                case LogLevel::DEBUG:    return "DEBUG";
                case LogLevel::INFO:     return "INFO";
                case LogLevel::NOTICE:   return "NOTICE";
                case LogLevel::WARNING:  return "WARNING";
                case LogLevel::ERROR:    return "ERROR";
                case LogLevel::CRITICAL: return "CRITICAL";
                case LogLevel::CRASH:    return "CRASH";
            }
            
            return "UNKNOWN";
        }

        static std::string getCurrentTime() {
            const std::time_t now = std::time(nullptr);
            char buffer[20];

            std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

            return buffer;
        }

    public:
        explicit Logger(std::string loggerName) : defaultName(std::move(loggerName)) {}

        Logger(std::string loggerName, bool debuggingEnabled) : defaultName(std::move(loggerName)),
                                                                debuggingEnabled(debuggingEnabled) {}

        Logger(std::string loggerName, std::string format) : defaultName(std::move(loggerName)),
                                                             format(std::move(format)) {}

        Logger(std::string loggerName, std::string format, bool debuggingEnabled) : defaultName(std::move(loggerName)),
                                                                                    format(std::move(format)),
                                                                                    debuggingEnabled(debuggingEnabled) {}

        bool debuggingEnabled = true;

        void println(const std::string &message, LogLevel level) {
            const std::string formattedMessage = replacePlaceholders(message, level);

            printWithColor(formattedMessage, level);

            std::cout << '\n';
        }

        FASTLOGGER_LOGGING_FUNCTION(trace, TRACE, true);
        FASTLOGGER_LOGGING_FUNCTION(debug, DEBUG, true);
        FASTLOGGER_LOGGING_FUNCTION(info, INFO, false);
        FASTLOGGER_LOGGING_FUNCTION(notice, NOTICE, false);
        FASTLOGGER_LOGGING_FUNCTION(warning, WARNING, false);
        FASTLOGGER_LOGGING_FUNCTION(error, ERROR, false);
        FASTLOGGER_LOGGING_FUNCTION(crash, CRASH, false);
        FASTLOGGER_LOGGING_FUNCTION(critical, CRITICAL, false);

    private:
        const std::string defaultName;
        const std::string format = "%date% %level% %loggerName% | %message%";

        [[nodiscard]] std::string replacePlaceholders(const std::string &message, LogLevel level) const {
            std::string formattedMessage = format;

            formattedMessage = replace(formattedMessage, "%message%", message);
            formattedMessage = replace(formattedMessage, "%level%", logLevelToString(level));
            formattedMessage = replace(formattedMessage, "%date%", getCurrentTime());
            formattedMessage = replace(formattedMessage, "%loggerName%", defaultName);

            return formattedMessage;
        }

        static std::string replace(const std::string &inputString, const std::string &from, const std::string &to) {
            size_t startPos = inputString.find(from);

            if (startPos != std::string::npos) {
                return inputString.substr(0, startPos) + to + inputString.substr(startPos + from.length());
            }

            return inputString;
        }

        static void printWithColor(const std::string &message, LogLevel level) {
#ifdef _WIN32
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
            WORD originalAttrs;

            GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
            originalAttrs = consoleInfo.wAttributes;

            switch (level) {
                case LogLevel::TRACE:
                    SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_BLUE); // Blue
                    break;
                case LogLevel::DEBUG:
                case LogLevel::INFO:
                    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN); // Green
                    break;
                case LogLevel::NOTICE:
                    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE); // Cyan
                    break;
                case LogLevel::WARNING:
                    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // Yellow
                    break;
                case LogLevel::ERROR:
                case LogLevel::CRITICAL:
                    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY); // Intense red
                    break;
                case LogLevel::CRASH:
                    SetConsoleTextAttribute(hConsole, BACKGROUND_RED | FOREGROUND_INTENSITY); // White on red background
                    break;
            }

            std::cout << message;

            SetConsoleTextAttribute(hConsole, originalAttrs);
#else
            switch (level) {
                case LogLevel::TRACE:
                    std::cout << "\033[34m" << message << "\033[0m"; // Blue
                    break;
                case LogLevel::DEBUG:
                case LogLevel::INFO:
                    std::cout << "\033[32m" << message << "\033[0m"; // Green
                    break;
                case LogLevel::NOTICE:
                    std::cout << "\033[34m" << message << "\033[0m"; // Blue
                    break;
                case LogLevel::WARNING:
                    std::cout << "\033[33m" << message << "\033[0m"; // Yellow
                    break;
                case LogLevel::ERROR:
                    std::cout << "\033[31m" << message << "\033[0m"; // Red
                    break;
                case LogLevel::CRITICAL:
                    std::cout << "\033[1;31m" << message << "\033[0m"; // Bold red
                    break;
                case LogLevel::CRASH:
                    std::cout << "\033[1;41;97m" << message << "\033[0m"; // Bold red background
                    break;
            }
#endif
        }
    };

    class DefaultLogger {
    public:
        static inline Logger* logger{nullptr};
    };
}

#endif // FASTLOGGER_1_LOGGER_HPP
