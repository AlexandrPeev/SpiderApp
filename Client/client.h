#include <string>
#include <thread>
#include "chat.pb.h"

class ChatClient {
public:
    ChatClient();
    ~ChatClient();

    bool connect(const std::string& server_ip, int port);
    bool sendMessage(const chat::ChatMessage& msg);
    bool receiveMessage(chat::ChatMessage& msg);
    void receiveLoop();
    bool login(const std::string& user, bool admin);
    bool sendChatMessage(const std::string& message);
    bool kickClient(const std::string& targetUsername);
    void stop();

    bool isRunning() const;
    bool isAuthenticated() const;
    bool isAdmin() const;

    private:
    int socket_fd;
    bool admin;
    std::string username;
    bool auth;
    bool running;
    std::thread receiveThrd;
};