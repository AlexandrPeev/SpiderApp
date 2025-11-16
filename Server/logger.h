#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <mutex>

class Logger {
public:
    Logger();
    
    void logMessage(const std::string& username, const std::string& message);

private:
    std::string createLogFileName() const;
    
    std::string logFile;
    mutable std::mutex logMutex;
};

#endif

