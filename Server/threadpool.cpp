#include "threadpool.h"
#include <iostream>

ThreadPool::ThreadPool(size_t numThreads) : numThreads(numThreads), stopFlag(false) {
    for (size_t i = 0; i < numThreads; ++i) {
        workers.emplace_back(&ThreadPool::worker, this);
    }
}

ThreadPool::~ThreadPool() {
    stop();
}

void ThreadPool::worker() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);

            condition.wait(lock, [this] {
                return !tasks.empty() || stopFlag.load();
            });
        
            if (stopFlag.load() && tasks.empty())
                return;

            task = std::move(tasks.front());
            tasks.pop();
        }
        task();
    }
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        if (stopFlag.load())
            return;
        tasks.push(std::move(task));
    }
    condition.notify_one();
}

void ThreadPool::stop() {
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        stopFlag.store(true);
        while (!tasks.empty())
            tasks.pop();
    }

    condition.notify_all();
    for (std::thread& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    workers.clear();
}

bool ThreadPool::isRunning() const {
    return !stopFlag.load();
}

