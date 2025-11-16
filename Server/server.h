#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <map>
#include <memory>
#include <mutex>
#include "chat.pb.h"
#include <thread>
#include <chrono>
#include "database.h"
#include "logger.h"
#include "threadpool.h"

struct Client {
    Client(int socket_fd_in, const std::string& ip_address);

    int socket_fd;
    std::string username;
    std::string ipAddr; 
    std::chrono::steady_clock::time_point connectionTime;
    std::chrono::steady_clock::time_point lastActivity;
    bool auth;
    bool isAdmin;
};

class Server {
    public:
    Server();
    ~Server();

    void handleClient(int socked_fd, const std::string& ip_address);
    bool distributeMessage(const chat::ChatMessage& msg, int antiID_fd);
    bool sendMessage(int socket_fd, const chat::ChatMessage& msg);
    bool receiveMessage(int socket_fd, chat::ChatMessage& msg);
    void inactivityCheck();

    bool start();
    void stop();
    void printClients();
    private:
    bool running;

    private:
    int serverSocket;
    std::map<int, std::shared_ptr<Client>> clients;
    mutable std::mutex clientsMutex;
    std::thread inactivityChecker;
    Database db;
    Logger logger;
    ThreadPool clientThreadPool;
};

#endif