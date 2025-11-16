#include "logger.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>

Logger::Logger() {
    logFile = createLogFileName();
}

std::string Logger::createLogFileName() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm* tm = std::localtime(&time_t);
    tm->tm_min = 0;
    tm->tm_sec = 0;
    std::ostringstream oss;
    oss << "chat_log_" << std::put_time(tm, "%Y%m%d_%H") << ".txt";
    return oss.str();
}

void Logger::logMessage(const std::string& username, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::string currentLogFile = createLogFileName();
    if (currentLogFile != logFile)
        logFile = currentLogFile;
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm* tm = std::localtime(&time_t);
    std::ofstream log(logFile, std::ios::app);
    if (log.is_open()) {
        log << "[" <<std::put_time(tm, "%Y-%m-%d %H:%M:%S") << "] "
            << username << ": " <<message << std::endl;
        log.flush();
    } else {
        std::cerr << "Failed to open log file: " <<logFile <<std::endl;
    }
}

