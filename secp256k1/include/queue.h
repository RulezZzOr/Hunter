#ifndef QUEUE_H
#define QUEUE_H
#include "definitions.h"
#include <mutex>
#include <condition_variable>
#include <vector>
#include <deque>
#include <iostream>
#include <cstring>
// all that we need to send to node/pool
struct MinerShare
{
    MinerShare();
    MinerShare(uint64_t _nonce, uint8_t *_w, uint8_t *_d)
    {
        nonce = _nonce;
        memcpy(pubkey_w, _w, PK_SIZE_8);
        memcpy(d, _d, NUM_SIZE_8);
        jobIdLen = 0;
        extraNonce2Size = 0;
    }
    MinerShare(uint64_t _nonce, uint8_t *_w, uint8_t *_d,
               const char *jobIdSrc, int jobIdLenSrc,
               const uint8_t *ex2, int ex2Size)
    {
        nonce = _nonce;
        memcpy(pubkey_w, _w, PK_SIZE_8);
        memcpy(d, _d, NUM_SIZE_8);
        jobIdLen = (jobIdLenSrc > (int)sizeof(jobId)) ? (int)sizeof(jobId) : jobIdLenSrc;
        if (jobIdLen > 0 && jobIdSrc)
        {
            memset(jobId, 0, sizeof(jobId));
            memcpy(jobId, jobIdSrc, jobIdLen);
        }
        else
        {
            jobIdLen = 0;
            jobId[0] = '\0';
        }

        extraNonce2Size = (ex2Size > (int)sizeof(extraNonce2)) ? (int)sizeof(extraNonce2) : ex2Size;
        if (extraNonce2Size > 0 && ex2)
        {
            memcpy(extraNonce2, ex2, extraNonce2Size);
        }
        else
        {
            extraNonce2Size = 0;
        }
    }
    uint64_t nonce;
    uint8_t pubkey_w[PK_SIZE_8];
    uint8_t d[NUM_SIZE_8];
    char jobId[64];
    int jobIdLen;
    uint8_t extraNonce2[32];
    int extraNonce2Size;
};

//simple blocking queue for solutions sending
template<class T> class BlockQueue
{
    std::deque<T> cont;
    std::mutex mut;
    std::condition_variable condv;
public:    
    void put(T &val)
    {
        mut.lock();
        cont.push_front(val);
        mut.unlock();
        condv.notify_one();

    }
    
    void put(T &&val)
    {
        mut.lock();
        cont.push_front(val);
        mut.unlock();
        condv.notify_one();

    }

    T get()
    {
        std::unique_lock<std::mutex> lock(mut);
        condv.wait(lock, [=]{ 
            return !cont.empty(); });
        T tmp = cont.back();
        cont.pop_back();
        return tmp;
    }
};



#endif
