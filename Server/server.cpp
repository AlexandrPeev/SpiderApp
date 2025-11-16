#include "server.h"
#include "chat.pb.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <iostream>
#include <vector>
#include <chrono>
#include "sqlite3.h"

#define PORT 8080
#define MAX_CLIENTS 50
#define TIMEOUT 600

Client::Client(int socket_fd_in, const std::string& ip_address)
: socket_fd(socket_fd_in),
  ipAddr(ip_address),
  connectionTime(std::chrono::steady_clock::now()),
  lastActivity(connectionTime),
  auth(false),
  isAdmin(false) {}

Server::Server() : serverSocket(-1), running(false), clientThreadPool(MAX_CLIENTS) {
}

Server::~Server() {
    if (serverSocket != -1)
        close(serverSocket);
}

bool Server::start() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSocket<0) {
        std::cerr << "Error creating socket" <<std::endl;
        return false;
    }
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if(bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr<< "Error binding serverSocket"<<std::endl;
        return false;
    }

    if(listen(serverSocket, MAX_CLIENTS) < 0) {
        std::cerr<< "Error listening"<<std::endl;
        return false;
    }
    running = true;
    inactivityChecker = std::thread(&Server::inactivityCheck, this);

    while(running) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);

        if(clientSocket < 0)
            continue;
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            if(clients.size() >= MAX_CLIENTS) {
                close(clientSocket);
                continue;
            }
        }

        std::string clientIp = inet_ntoa(clientAddr.sin_addr);
        clientThreadPool.enqueue([this, clientSocket, clientIp]() {
            this->handleClient(clientSocket, clientIp);
        });
    }
    return true;
}

bool Server::sendMessage(int socket_fd,const chat::ChatMessage& msg) {
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

bool Server::receiveMessage(int socket_fd, chat::ChatMessage& msg) {
    int length;
    ssize_t received = recv(socket_fd, &length, sizeof(length), MSG_WAITALL);
    if (received != sizeof(length) || received <= 0) {
        return false;
    }
    
    std::vector<char> buffer(length);
    received = recv(socket_fd, buffer.data(), length, MSG_WAITALL);
    if (received != length || received <= 0) {
        return false;
    }
    return msg.ParseFromArray(buffer.data(), length);
}

bool Server::distributeMessage(const chat::ChatMessage& msg, int antiID_fd) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for( const auto& it : clients) {
        if(it.first != antiID_fd && it.second->auth) {
            sendMessage(it.first, msg);
        }
    }
    return true;
}

void Server::handleClient(int socket_fd, const std::string& ip_address) {
    auto client = std::make_shared<Client>(socket_fd,ip_address);
    {
        std::lock_guard<std::mutex> guard(clientsMutex);
        clients[socket_fd] = client;
    }
    std::cout << "Client connected from ip: " << ip_address <<std::endl;
    chat::ChatMessage msg;
    while(running) {
        msg.Clear();
        if(!receiveMessage(socket_fd, msg))
            break;
        client->lastActivity = std::chrono::steady_clock::now();
        switch (msg.type()) {
            case chat::LOGIN: {
                bool usernameTaken = false;
                std::string username = msg.username();
                {
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    for(const auto& it: clients) {
                        if(it.second->username == username) {
                            usernameTaken = true;
                            break;
                        }
                    }
                }
                bool isAdmin = msg.is_admin();
                chat::ChatMessage resp;
                if (usernameTaken || username.empty()) {
                resp.set_type(chat::LOGIN_RESPONSE);
                resp.set_login_success(false);
                resp.set_error_message("Username already taken or invalid");
                if (!sendMessage(socket_fd, resp)) {
                    std::cerr << "Failed to send login response (failed)" << std::endl;
                }
                } else {
                    client->username = username;
                    client->auth = true;
                    client->isAdmin = isAdmin;

                    resp.set_type(chat::LOGIN_RESPONSE);
                    resp.set_login_success(true);
                    resp.set_is_admin(isAdmin);
                    if (!sendMessage(socket_fd, resp)) {
                        std::cerr << "Failed to send login response (success)" << std::endl;
                    }
                    
                    std::cout << "Client " << username << " authenticated from " 
                              << ip_address << std::endl
                              << ip_address << (isAdmin ? " (ADMIN)" : "") << std::endl;
                }
                break;
            }

            case chat::CHAT_MESSAGE: {
                if (!client->auth) break;
                
                std::string messageText = msg.message_text();
                logger.logMessage(client->username, messageText);
                db.saveMessage(client->username, messageText);

                chat::ChatMessage broadcastMsg;
                broadcastMsg.set_type(chat::CHAT_BROADCAST);
                broadcastMsg.set_message_text(messageText);
                broadcastMsg.set_sender_username(client->username);
                broadcastMsg.set_timestamp(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count()
                );
                
                distributeMessage(broadcastMsg, socket_fd);
                break;
            }

            case chat::KICK_CLIENT: {
                if (!client->auth) break;
                
                if (!client->isAdmin) {
                    chat::ChatMessage error_response;
                    error_response.set_type(chat::ERROR);
                    error_response.set_error_message("You are not an admin");
                    sendMessage(socket_fd, error_response);
                    break;
                }
                
                std::string targetUsername = msg.target_username();
                int target_fd = -1;
                
                {
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    for (const auto& it : clients) {
                        if (it.second->auth && it.second->username == targetUsername) {
                            target_fd = it.first;
                            break;
                        }
                    }
                }
                
                if (target_fd != -1) {
                    chat::ChatMessage kickNotification;
                    kickNotification.set_type(chat::KICK_NOTIFICATION);
                    kickNotification.set_error_message("You have been kicked from the server by an administrator");
                    sendMessage(target_fd, kickNotification);
                    
                    close(target_fd);
                    {
                        std::lock_guard<std::mutex> lock(clientsMutex);
                        clients.erase(target_fd);
                    }
                    
                    std::cout << "Client " << targetUsername << " was kicked by admin " 
                              << client->username << std::endl;
                } else {
                    chat::ChatMessage errorResponse;
                    errorResponse.set_type(chat::ERROR);
                    errorResponse.set_error_message("Client not found: " + targetUsername);
                    sendMessage(socket_fd, errorResponse);
                }
                break;
            }

            default:
            break;
        }
    }

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        std::string username = client->username.empty() ? "(not authenticated)" : client->username;
        clients.erase(socket_fd);
        std::cout << "Client disconnected: " << username << std::endl;
    }
    close(socket_fd);
}

void Server::inactivityCheck() {
    while(running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        auto now = std::chrono::steady_clock::now();
        std::vector<int> disconnect;

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            for(const auto& it: clients) {
                if(it.second->auth) {
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - it.second->lastActivity);
                    if (duration.count() > TIMEOUT) {
                        disconnect.push_back(it.first);
                    }
                }
            }
        }

        for(int fd: disconnect) {
            close(fd);
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                clients.erase(fd);
            }
            std::cout<< "Client disconnected due to inactivity"<< std::endl;
        }
    }
}

void Server::stop() {
    running = false;
    if(serverSocket != -1) {
        shutdown(serverSocket, SHUT_RDWR);
        close(serverSocket);
        serverSocket = -1;
    }

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        for (const auto& it : clients) {
            shutdown(it.first, SHUT_RDWR);
            close(it.first);
        }
        clients.clear();
    }
    
    if(inactivityChecker.joinable()) {
        inactivityChecker.join();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    clientThreadPool.stop();
}


void Server::printClients() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    std::cout << "Connected Clients:" << std::endl;
    std::cout << "Number: " << clients.size() << std::endl;
    
    for (const auto& it: clients) {
        if (it.second->auth) {
            auto now = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - it.second->connectionTime);
            
            std::cout << "Username: " << it.second->username
                      << ", IP: " << it.second->ipAddr
                      << ", Time online: " << duration.count() << " seconds" << std::endl;
        }
    }
}
