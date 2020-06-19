#include "ThreadsafeQueue.h"

template <typename T>
ThreadsafeQueue<T>::ThreadsafeQueue(){
    pthread_mutex_init(&this->mutex, NULL);
}

template <typename T>
ThreadsafeQueue<T>::~ThreadsafeQueue(){
    pthread_mutex_destroy(&this->mutex);
}

template <typename T>
T& ThreadsafeQueue<T>::pop(){
    T& result = std::nullptr_t;
    lock(); //might want to make this wait until theres an element
    if(!queue.empty()){
        result = queue.front();
        queue.pop();
    }
    unlock();
    return result;
}

template <typename T>
void ThreadsafeQueue<T>::push(T& t){
    lock();
    queue.push(t);
    unlock();
}

template <typename T>
int ThreadsafeQueue<T>::size(){
    int result = 0;
    lock();
    result = queue.size();
    unlock();
    return result;
}

template <typename T>
bool ThreadsafeQueue<T>::empty(){
    bool result = false;
    lock();
    result = queue.empty();
    unlock();
    return result;
}

template <typename T>
bool ThreadsafeQueue<T>::lock(){
    return pthread_mutex_lock(&this->mutex) == 0;
}

template <typename T>
bool ThreadsafeQueue<T>::unlock(){
    return pthread_mutex_unlock(&this->mutex) == 0;
}

