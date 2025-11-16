#include <iostream>
#include "server.h"

int main() {
    Server server;

    std::thread server_thread([&server]() { server.start();});
    std::cout << "Chat Server Commands:" << std::endl;
    std::cout << "  'list' - Show connected clients" << std::endl;
    std::cout << "  'quit' - Shutdown server" << std::endl;

    std::string command;
    while (true) {
        std::cin >> command;
        if (command == "list") {
            server.printClients();
        } else if (command == "quit") {
            server.stop();
            break;
        }
    }
    
    if (server_thread.joinable()) {
        server_thread.join();
    }
    return 0;
}