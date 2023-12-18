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
        }

        static std::string getCurrentTime() {
            const std::time_t now = std::time(nullptr);
            char buffer[20];

            std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

            return buffer;
        }

    public:
        explicit Logger(std::string loggerName) : defaultName(std::move(loggerName)) {}

        Logger(std::string loggerName, bool debuggingEnabled) : defaultName(std::move(loggerName)), debuggingEnabled(debuggingEnabled) {}

        Logger(std::string loggerName, std::string format) : defaultName(std::move(loggerName)), format(std::move(format)) {}

        Logger(std::string loggerName, std::string format, bool debuggingEnabled) : defaultName(std::move(loggerName)), format(std::move(format)), debuggingEnabled(debuggingEnabled) {}

        bool debuggingEnabled = true;

        void println(const std::string& message, LogLevel level) {
            const std::string formattedMessage = replacePlaceholders(message, level);

            printWithColor(formattedMessage, level);

            std::cout << '\n';
        }

        void trace(const std::string& message) {
            if (debuggingEnabled) {
                println(message, LogLevel::TRACE);
            }
        }

        void debug(const std::string& message) {
            if (debuggingEnabled) {
                println(message, LogLevel::DEBUG);
            }
        }

        void info(const std::string& message) {
            println(message, LogLevel::INFO);
        }

        void notice(const std::string& message) {
            println(message, LogLevel::NOTICE);
        }

        void warning(const std::string& message) {
            println(message, LogLevel::WARNING);
        }

        void error(const std::string& message) {
            println(message, LogLevel::ERROR);
        }

        void crash(const std::string& message) {
            println(message, LogLevel::CRASH);
        }

        void critical(const std::string& message) {
            println(message, LogLevel::CRITICAL);
        }

    private:
        const std::string defaultName;
        const std::string format = "%date% %level% %loggerName% | %message%";

        [[nodiscard]] std::string replacePlaceholders(const std::string& message, LogLevel level) const {
            std::string formattedMessage = format;

            formattedMessage = replace(formattedMessage, "%message%", message);
            formattedMessage = replace(formattedMessage, "%level%", logLevelToString(level));
            formattedMessage = replace(formattedMessage, "%date%", getCurrentTime());
            formattedMessage = replace(formattedMessage, "%loggerName%", defaultName);

            return formattedMessage;
        }

        static std::string replace(const std::string& inputString, const std::string& from, const std::string& to) {
            size_t startPos = inputString.find(from);

            if (startPos != std::string::npos) {
                return inputString.substr(0, startPos) + to + inputString.substr(startPos + from.length());
            } else {
                return inputString;
            }
        }

        static void printWithColor(const std::string& message, LogLevel level) {
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
                    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY); // Intense Red
                    break;
                case LogLevel::CRASH:
                    SetConsoleTextAttribute(hConsole, BACKGROUND_RED | FOREGROUND_INTENSITY); // White on Red background
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
                    std::cout << "\033[1;31m" << message << "\033[0m"; // Bold Red
                    break;
                case LogLevel::CRASH:
                    std::cout << "\033[1;41;97m" << message << "\033[0m"; // Bold Red background
                    break;
            }
#endif
        }
    };
}

#endif // FASTLOGGER_1_LOGGER_HPP
