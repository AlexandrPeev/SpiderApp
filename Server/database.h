#ifndef DATABASE_H
#define DATABASE_H

#include "sqlite3.h"
#include <string>

class Database {
    public:
    Database();
    ~Database();
    void saveMessage(const std::string& username, const std::string& message);
    private:
    sqlite3* db;
};

#endif