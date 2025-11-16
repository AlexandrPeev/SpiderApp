#include <iostream>
#include <thread>
#include <chrono>
#include "client.h"

#define SERVER_IP "127.0.0.1"
#define PORT 8080

int main() {
    ChatClient client;
    if(!client.connect(SERVER_IP, PORT)) {
        std::cerr<< "Failed to connect to server: "<<SERVER_IP<< std::endl;
        return 1;
    }
    std::cout << "Connected to server. Enter username: ";
    std::string username;
    std::getline(std::cin, username);

    std::cout << "Login as admin? (y/n): ";
    std::string admin_input;
    std::getline(std::cin, admin_input);

    bool admin = admin_input == "y";
    
    if (!client.login(username, admin)) {
        std::cerr << "Failed to send login request" << std::endl;
        client.stop();
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    if (!client.isAuthenticated()) {
        std::cerr<< "Authentication failed" <<std::endl;
        client.stop();
        return 1;
    }

    std::cout << "\nChat Commands:" << std::endl;
    if (client.isAdmin())
        std::cout << "  /kick <username> - Kick a client (admin only)" << std::endl;
    std::cout << "  /quit - Disconnect" << std::endl;
    std::cout << "\nChat start:\n" << std::endl;

    std::string input;
    while (client.isRunning()) {
        std::cout << "> ";
        std::getline(std::cin, input);
        
        if (!client.isRunning())
            break;
            
        if (input.empty())
            continue;
        
        if (input == "/quit") {
            client.stop();
            break;
        } else if (input.substr(0, 6) == "/kick ") {
            std::string target = input.substr(6);
            client.kickClient(target);
        } else {
            client.sendChatMessage(input);
        }
    }
    
    client.stop();
    return 0;
}