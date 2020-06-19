#pragma once
#include <pthread.h>
#include <queue>

template <typename T>
class ThreadsafeQueue
{
    public:
        ThreadsafeQueue();
        ~ThreadsafeQueue();

        T& pop();
        void push(T& t);
        int size();
        bool empty();

    private:
        std::queue<T> queue;
        pthread_mutex_t mutex;

        bool lock();

        bool unlock();

};