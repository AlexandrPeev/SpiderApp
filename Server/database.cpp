#include "database.h"
#include <iostream>

Database::Database() {
    int res = sqlite3_open("chat.db", &db);
    if(res) {
        std::cerr << "Error opening db: " << sqlite3_errmsg(db)<< std::endl;
    }
    const char* create_users = 
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";
    
    const char* create_messages = 
        "CREATE TABLE IF NOT EXISTS messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "user_id INTEGER,"
        "username TEXT NOT NULL,"
        "message TEXT NOT NULL,"
        "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "FOREIGN KEY(user_id) REFERENCES users(id)"
        ");";
    
    sqlite3_exec(db, create_users, nullptr, nullptr, nullptr);
    sqlite3_exec(db, create_messages, nullptr, nullptr, nullptr);
}

void Database::saveMessage(const std::string& username, const std::string& message) {
    
    const char* insert_user = "INSERT OR IGNORE INTO users (username) VALUES (?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, insert_user, -1,  &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    const char* insert_message = "INSERT INTO messages (username, message) VALUES (?, ?);";
    sqlite3_prepare_v2(db, insert_message, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, message.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

Database::~Database() {
    if (db)
        sqlite3_close(db);
}