#include "client.h"
#include <iomanip>
#include <cstring>
#include <vector>
#include <chrono>
#include <ctime>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080

ChatClient::ChatClient() : socket_fd(-1), auth(false), admin(false), running(false) {}

ChatClient::~ChatClient() {
    stop();
}

bool ChatClient::connect(const std::string& server_ip, int port) {
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd < 0) {
        std::cerr<< "Error creating the socket"<<std::endl;
        return false;
    }
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if(inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address" << std::endl;
        close(socket_fd);
        socket_fd = -1;
        return false;
    }
    if(::connect(socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr<< "Connection failed"<< std::endl;
        close(socket_fd);
        socket_fd = -1;
        return false;
    }

    running = true;
    receiveThrd = std::thread(&ChatClient::receiveLoop, this);
    return true;
}

void ChatClient::receiveLoop() {
    chat::ChatMessage msg;
    while (running) {
        if (!receiveMessage(msg)) {
            if (running) {
                std::cout << "\nConnection lost to server" << std::endl;
            }
            running = false;
            break;
        }
    
        switch(msg.type()) {
            case chat::LOGIN_RESPONSE: {
                if(msg.login_success()) {
                    auth = true;
                    admin = msg.is_admin();
                    std::cout << "Login Successful: " << username << " is admin?: " <<admin<<std::endl;
                } else {
                    std::cout << "Login Failed:" <<msg.error_message() <<std::endl;
                    running = false;
                }
                break;
            }
            case chat::CHAT_BROADCAST: {
                auto timestamp = std::chrono::system_clock::from_time_t(msg.timestamp());
                auto time_t = std::chrono::system_clock::to_time_t(timestamp);
                std::tm* tm = std::localtime(&time_t);
                
                std::cout << "\n[" << std::put_time(tm, "%H:%M:%S") << "] "
                          << msg.sender_username() << ": " << msg.message_text() <<std::endl;
                std::cout << "> " << std::flush;
                break;
            }

            case chat::KICK_NOTIFICATION: {
                std::cout << "\n" << msg.error_message() << std::endl;
                running = false;
                break;
            }

            case chat::ERROR: {
                std::cout << "\nError: " << msg.error_message() << std::endl;
                std::cout << "> " << std::flush;
                break;
            }

            default:
                break;
        }
    }
}

bool ChatClient::login(const std::string& user, bool admin){
    username = user;
    chat::ChatMessage msg;
    msg.set_type(chat::LOGIN);
    msg.set_username(username);
    msg.set_is_admin(admin);
    return sendMessage(msg);
}

bool ChatClient::sendChatMessage(const std::string& message) {
    if (!auth)
        return false;
    
    chat::ChatMessage msg;
    msg.set_type(chat::CHAT_MESSAGE);
    msg.set_message_text(message);
    return sendMessage(msg);
}

bool ChatClient::kickClient(const std::string& target_username) {
    if (!auth || !admin) {
        return false;
    }
    
    chat::ChatMessage msg;
    msg.set_type(chat::KICK_CLIENT);
    msg.set_target_username(target_username);
    return sendMessage(msg);
}

bool ChatClient::isRunning() const {
    return running;
}

bool ChatClient::isAuthenticated() const {
    return auth;
}

bool ChatClient::isAdmin() const {
    return admin;
}

void ChatClient::stop() {
    running = false;
    if (socket_fd != -1) {
        shutdown(socket_fd, SHUT_RDWR);
        close(socket_fd);
        socket_fd = -1;
    }
    if (receiveThrd.joinable())
        receiveThrd.join();
}

bool ChatClient::sendMessage(const chat::ChatMessage& msg) {
    std::string result;
    if(!msg.SerializeToString(&result))
        return false;

    int length = result.size();
    if(send(socket_fd, &length, sizeof(length), 0) < 0)
        return false;

    if(send(socket_fd, result.c_str(), result.size(), 0) < 0)
        return false;
    return true;
}

bool ChatClient::receiveMessage(chat::ChatMessage& msg) {
    int length;
    if (recv(socket_fd, &length, sizeof(length), MSG_WAITALL) != sizeof(length)) {
        return false;
    }
    
    std::vector<char> buffer(length);
    if (recv(socket_fd, buffer.data(), length, MSG_WAITALL) != length) {
        return false;
    }
    return msg.ParseFromArray(buffer.data(), length);
}

