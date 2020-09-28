#include <pthread.h>
#include <map>
#include <optional>

template<typename K, typename V>
using MapIterator = typename std::map<K, V>::iterator;

template<typename K, typename V>
class ThreadsafeMap{
private:
    pthread_mutex_t mutex;
    std::map<K, V> map;
public:
    ThreadsafeMap();

    ~ThreadsafeMap();

    void put(K& key, V& value);

    std::optional<V&> get(K& key);

    bool contains(K& key);

    void remove(K& key);

    size_t size();
};