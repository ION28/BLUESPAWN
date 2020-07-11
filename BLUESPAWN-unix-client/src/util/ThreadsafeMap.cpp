#include "ThreadsafeMap.h"

template<typename K, typename V>
ThreadsafeMap<K, V>::ThreadsafeMap(){
    pthread_mutex_init(&this->mutex, NULL);
}

template<typename K, typename V>
ThreadsafeMap<K, V>::~ThreadsafeMap(){
    pthread_mutex_destroy(&this->mutex, NULL);
}

template<typename K, typename V>
void ThreadsafeMap<K, V>::put(K& key, V& value){
    pthread_mutex_lock(&this->mutex);
    this->map.insert(std::pair<K, V>(key, value));
    pthread_mutex_unlock(&this->mutex);
}

template<typename K, typename V>
std::optional<V&> ThreadsafeMap<K, V>::get(K& key){
    pthread_mutex_lock(&this->mutex);
    std::map<K, V>::iterator itr;
    for (itr = this->map.begin(); itr != this->map.end(); ++itr) { 
        if(itr->first == key){
            pthread_mutex_unlock(&this->mutex);
            return itr->second;
        }
    }

    pthread_mutex_unlock(&this->mutex);
    return std::nullopt;
}

template <typename K, typename V>
bool ThreadsafeMap<K, V>::contains(K& key){
    return this->get(key).has_value();
}

template<typename K, typename V>
void ThreadsafeMap<K, V>::remove(K& key){
    pthread_mutex_unlock(&this->mutex);
    this->map.erase(key);
    pthread_mutex_unlock(&this->mutex);
}

template<typename K, typename V>
size_t ThreadsafeMap<K, V>::size(){
    return this->map.size();
}