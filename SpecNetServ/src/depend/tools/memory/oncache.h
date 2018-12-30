#ifndef ONCACHE_H
#define ONCACHE_H

#include <stdlib.h>
#include <string.h>
#include <cassert>
#include <cmath>
#if defined(Windows)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

//Для быстрой работы на same hash надо пару уровней на нижний этаж добавить
//TODO для вау эффекта
#define SKIPHEIGHT 5
#define SKIPHEIGHT_H 2
#define SIZEAllocLeaf 256


typedef void (*TDeletDataFunc)(const char *data);

//TODO any size key implementation:
template<typename T>
union AnySizeKey {
    T key;
    static constexpr int keyLongSize = ((sizeof(T)/sizeof(long long))+ (sizeof(T)%sizeof(long long)>0?1:0));
    unsigned long long keyArray[keyLongSize];
    int cmp(AnySizeKey const & other ) {
        for (int i=0; i<keyLongSize; ++i) {
            if (keyArray[i]>other.keyArray[i]) return 1;
            if (keyArray[i]<other.keyArray[i]) return -1;
        }
        return 0;
    }
};

struct {
    uint32_t spec_mark;
    uint32_t body_len;  //with T_IPack0_Header
    uint32_t pack_type;
    uint64_t key1;
    uint64_t key2;
    uint64_t key3;
} typedef TKey;



//class TKey {
//public:
//    //Последней в ключе должна идти дата - её буду сравнивать первой
//    TKey(unsigned long long p0, unsigned long long p1, unsigned long long p2){
//        keyArray[0] = p0;
//        keyArray[1] = p1;
//        keyArray[2] = p2;
//    }

//    TKey & operator=(TKey const& rhl){
//        keyArray[0] = rhl.keyArray[0];
//        keyArray[1] = rhl.keyArray[1];
//        keyArray[2] = rhl.keyArray[2];
//        return *this;
//    }

//    TKey(const TKey &rhl) {
//        keyArray[0] = rhl.keyArray[0];
//        keyArray[1] = rhl.keyArray[1];
//        keyArray[2] = rhl.keyArray[2];
//    }

//    bool operator==(TKey const& rhl) const {
//        return keyArray[0] == rhl.keyArray[0]
//            && keyArray[1] == rhl.keyArray[1]
//            && keyArray[2] == rhl.keyArray[2];
//    }

//    static constexpr int keyLongSize = 3;
//    unsigned long long keyArray[keyLongSize];
//    unsigned long long hash() const {
//        //TODO Worst case just return same hash or %N
//        const unsigned long long re = keyArray[0] + keyArray[1] + keyArray[2];
//        //return re<9223372036854775807ll?re:(re>>1);
//        return (re % 10);
//    }

//    int cmp(TKey const * other) const {
//        if (keyArray[2]>other->keyArray[2]) return 1;
//        if (keyArray[2]<other->keyArray[2]) return -1;

//        if (keyArray[1]>other->keyArray[1]) return 1;
//        if (keyArray[1]<other->keyArray[1]) return -1;

//        if (keyArray[0]>other->keyArray[0]) return 1;
//        if (keyArray[0]<other->keyArray[0]) return -1;

//        return 0;
//    }

//    bool operator<(const TKey& r) const {
//        if ( keyArray[0] < r.keyArray[0] )  return true;
//        if ( keyArray[0] > r.keyArray[0] )  return false;
//        if ( keyArray[1] < r.keyArray[1] )  return true;
//        if ( keyArray[1] > r.keyArray[1] )  return false;
//        if ( keyArray[2] < r.keyArray[2] )  return true;
//        if ( keyArray[2] > r.keyArray[2] )  return false;

//        // Otherwise both are equal
//        return false;
//    }

//};


//inline uint qHash(const TKey *key, uint seed = 0)
//{
//    return key->hash() ^ seed;
//}

//inline uint qHash(TKey key, uint seed = 0)
//{
//    return key.hash() ^ seed;
//}

//bool operator<(const TKey& l, const TKey& r ) {
//    if ( l.keyArray[0] < r.keyArray[0] )  return true;
//    if ( l.keyArray[0] > r.keyArray[0] )  return false;
//    if ( l.keyArray[1] < r.keyArray[1] )  return true;
//    if ( l.keyArray[1] > r.keyArray[1] )  return false;
//    if ( l.keyArray[2] < r.keyArray[2] )  return true;
//    if ( l.keyArray[2] > r.keyArray[2] )  return false;

//    // Otherwise both are equal
//    return false;
//}

class TONode {
public:
    TONode * fwdPtrs[SKIPHEIGHT];
    //rating queue:
    TONode * mostUseful;
    TONode * leastUseful;
    //const unsigned char * key;
    TKey const * key;
    const char * data;    
    unsigned char curHeight;// ==SKIPHEIGHT-1 to CPU economy
    unsigned long long hash;
};




class OnCache {
public:

    /*
     * capacity - how many elements can store
     * keyLen - memcmp third parameter
     * Key must be part of the stored Value - will deallocate Value only
    */
    OnCache(unsigned int capacity, //unsigned int keyLen,
           TDeletDataFunc f_delData)
        :_capacity(capacity),
          _f_delData(f_delData),
          _hash_baskets(sqrt(capacity)),
          //lvl2jump(sqrt(_hash_baskets)),
          //lvl1jump(sqrt(lvl2jump)),
          leafSize((_hash_baskets>256)?_hash_baskets:256) {

        init();
    }


    ~OnCache(){
        clear();
    }

    unsigned int size() {
        return _size;
    }


    const char * getData(TKey const * key) {
        TONode * curFound = find(key) ;
        if (curFound) {
            toTopUsage(curFound);
            return curFound->data;
        }
        return nullptr;
    }

    void insertNode (TKey const * key, const char * data){
        const unsigned long long hash = getHash(key);//key->hash();
        const unsigned short basketID = hash % _hash_baskets;
        //TONode * curBasket = &(baskets[basketID]);
        int cmp = setll(hash, key, basketID);
        if (0==cmp) {
            TONode * cur = updatePathOut[0];
             _f_delData(cur->data);
             cur->data = data;
             cur->key = key;
             toTopUsage(cur);
        } else {
            //insert new node:
            allocNode(hash, key, data, basketID, cmp);
        }

//        //old
//        OSkipList * curSkiList = getBasket(key);
//        TCacheNode * curFound = nullptr;
//        //int cmp = curSkiList->setll(key, curFound);
//        if (0==curSkiList->setll(key, curFound)) {
//            //found node with key is equal, replace data:
//            clearNode(*curFound);
//            curFound->data = data;
//            curFound->key  = key;
//        } else {
//            //insert new node:
//            curSkiList->insertNode(allocNode(key, data, curSkiList));
//        }
    }

private:
    const unsigned int _capacity;
    const unsigned short _hash_baskets;
   // const int _far_step;
    const unsigned short leafSize;
    //const unsigned short lvl2jump;
    //const unsigned short lvl1jump;


    //const unsigned int _keyLen;
    unsigned int _size;
    TONode * baskets;

    TONode * updatePathOut[SKIPHEIGHT];

    //Allocations:
    TONode * curLeaf;
    TONode ** curLeaf_NextPtr;
    TONode ** headLeaf;

    unsigned int leafAllocCounter;

    //Deallocations:
//    typedef void (*TDeletDataFunc)(const char *data);
    //TDeleteNodeDataFunc _f_delData;
    TDeletDataFunc _f_delData;

    //Rating queue:
    TONode headNode;

    //Landscapes
    unsigned char landscape_h[256];
    unsigned char * land_h_p;
    unsigned char landscape_l[256];
    unsigned char * land_l_p;


//    const unsigned int _hash_baskets;
//    const unsigned int _capacity;
//    const unsigned int _keyLen;
//    unsigned int leafAllocCounter;
//    unsigned int _size;
//    OSkipList * baskets;
//    TAllocLeaf headLeaf;
//    TAllocLeaf * curLeaf;
//    //rating queue:
//    TCacheNode headNode;
//    TDeletDataFunc _f_delData;

    unsigned long long getHash(TKey const * key) const {
        const unsigned long long re = key->key1 + key->key2 + key->key3;
        return re<9223372036854775807ll?re:(re>>1);
    }

    int getCmp(TKey const * first, TKey const * other) const {
        if (first->key2>other->key2) return 1;
        if (first->key2<other->key2) return -1;

        if (first->key1>other->key1) return 1;
        if (first->key1<other->key1) return -1;

        if (first->key3>first->key3) return 1;
        if (first->key3<first->key3) return -1;

        return 0;
    }

    void init(){
        //init basket lvl counters
        const size_t size1 = _hash_baskets * sizeof(unsigned char);
        land_h_p = (unsigned char *) malloc(size1);
        land_l_p = (unsigned char *) malloc(size1);
        memset(land_h_p,0,size1);
        memset(land_l_p,0,size1);

        landscape_h[0] = 4;
        landscape_l[0] = 1;
        const unsigned short lvl2jump = (sqrt(_hash_baskets));
        const unsigned short lvl1jump = (sqrt(lvl2jump));
        int delLvl2 = lvl2jump+1;
        int delLvl1 = lvl1jump+1;

        for (int i = 1; i<255;++i) {
            if (i%delLvl2>=lvl2jump) {
                landscape_h[i] = 4;
                landscape_l[i] = 0;
            } else if(i%delLvl1>=lvl1jump){
                landscape_h[i] = 3;
                landscape_l[i] = 1;
            } else {
                landscape_h[i] = 2;
                landscape_l[i] = 0;
            }
        }
        landscape_l[255] = 1;
        landscape_h[255] = 4;
//             std::cerr<<'\n';
//        for (int i = 0; i<256;++i) {
//            std::cerr<<('0'+landscape_h[i]);
//        }
//        std::cerr<<'\n'<<'\n'<<'\n';
//   for (int i = 0; i<256;++i) {
//       std::cerr<<('0'+landscape_l[i]);
//   }
//      std::cerr<<'\n'<<'\n'<<'\n';

        //init baskets:
        const size_t size2 =_hash_baskets * sizeof(TONode);
        baskets = (TONode *)malloc(size2);
        memset(baskets,0,size2);
        for (int i =0; i<_hash_baskets; ++i){ baskets[i].curHeight = 4;}

        //init allocations:
        const size_t size3 = sizeof(TONode * ) + leafSize * sizeof(TONode);
        headLeaf = curLeaf_NextPtr  = (TONode **)malloc(size3);
        memset(curLeaf_NextPtr,0,size3);
        curLeaf = (TONode * )(curLeaf_NextPtr + 1);
        *curLeaf_NextPtr = nullptr;
        leafAllocCounter = 0;
        _size = 0;

        //init rating queue:
        //headNode.clean();
        memset(&headNode,0,sizeof(TONode));
        headNode.mostUseful = &headNode;
        headNode.leastUseful = &headNode;
    } //init

    void clear(){
        //for ( unsigned int i = 0; i < _hash_baskets; ++i ) { baskets[i]=nullptr; }
        deleteLeaf(headLeaf);
        headLeaf = nullptr;
        curLeaf = nullptr;
        curLeaf_NextPtr = nullptr;
        leafAllocCounter = 0;
        _size  = 0;
       free(baskets);
       free(land_h_p);
       free(land_l_p);
    }

    void deleteLeaf(TONode ** ptr) {
        if (ptr) {
            if (*ptr) { deleteLeaf((TONode **) *ptr);}
            TONode * node = (TONode *)(ptr+1);
            if (curLeaf == node) {
                assert(!(*ptr)); //Удалить
                clearNodes(curLeaf, leafAllocCounter);
                curLeaf = nullptr;
                leafAllocCounter = 0;
            } else {
                clearNodes(node, leafSize);
            }
             free(ptr);
        }
    }


    void allocNode(const unsigned long long hash, TKey const * key, const char * data,
                  const unsigned short basketID, int cmp){
        TONode * re = nullptr;
        //TDNode * prevHead = updatePathOut?updatePathOut[0]:curBasket;
        TONode * prevHead = updatePathOut[0];
        //if (!prevHead) {prevHead=curBasket;}

        if (_capacity > _size) {

            if (leafSize==leafAllocCounter) {
                *curLeaf_NextPtr  = (TONode *)malloc(sizeof(TONode * ) + leafSize * sizeof(TONode));
                if (*curLeaf_NextPtr) {
                    //if alloc success
                    curLeaf_NextPtr = (TONode **)(*curLeaf_NextPtr);
                    curLeaf = (TONode * )(curLeaf_NextPtr + 1);
                    *curLeaf_NextPtr = nullptr;
                    leafAllocCounter = 0;
                    //_size = 0;
                }
            }

            if (leafSize > leafAllocCounter){
                re = curLeaf + leafAllocCounter;
                ++_size;
                ++leafAllocCounter;
            }
        }

        if (!re) {
            //reuse an older node
            re = headNode.leastUseful;
            headNode.leastUseful = re->mostUseful;
            re->mostUseful->leastUseful = &headNode;
            //check if this is head of basket:
//            if (re == (baskets[re->hash % _hash_baskets]).fwdPtrs[0]) {
//                if () //Too many calc for rare case
//            } else {               }

            if (hash == re->hash) {
                if (re != prevHead) {
                    delInSameBasket(re);
                    prevHead = updatePathOut[0];
                } //else will replace at place
            } else if (basketID==re->hash % _hash_baskets) {
                delInSameBasket(re);
                prevHead = updatePathOut[0];
            } else {
                delInOtherBacket(re);
            }

            _f_delData(re->data);            
        }

        //re->clean();
        memset(re,0,sizeof(TONode));
        //New leader = new:
        re->mostUseful = &headNode;
        re->leastUseful = headNode.mostUseful;
        headNode.mostUseful->mostUseful = re;
        if (&headNode==headNode.leastUseful) {
            //The first became last too:
            headNode.leastUseful = re;
        }
        headNode.mostUseful = re;
        re->hash = hash;
        if (cmp>0) {
            //using update path
            re->key = key;
            re->data = data;
            re->curHeight = 3==cmp?
                landscape_h[(land_h_p[basketID])++]
                    :landscape_l[(land_l_p[basketID])++];
            int i = 0;
            while (i<=re->curHeight) {
                re->fwdPtrs[i] = updatePathOut[i]->fwdPtrs[i];
                updatePathOut[i]->fwdPtrs[i] = re;
                ++i;
            }
            while (i<=SKIPHEIGHT) {
                re->fwdPtrs[i] = nullptr;
                ++i;
            }
        } else {
            //replace at place
            if (re == prevHead) {
                re->key = key;
                re->data = data;
            } else {
                re->key = prevHead->key;
                re->data = prevHead->data;
                re->curHeight = landscape_l[(land_l_p[basketID])++];
                re->fwdPtrs[0]=prevHead->fwdPtrs[0];
                prevHead->fwdPtrs[0] = re;
                if (1==re->curHeight) {
                    re->fwdPtrs[1]=prevHead->fwdPtrs[1];
                    prevHead->fwdPtrs[1] = re;
                }
                prevHead->key = key;
                prevHead->data = data;
            }
        }

        return;
    }

    TONode * find(TKey const * key) {
        //const unsigned long long hash = key->hash();
        const unsigned long long hash = getHash(key);
        const unsigned short basketID = hash % _hash_baskets;
        TONode * cur = &(baskets[basketID]);
        int h = 4;//cur->curHeight;
        while( h>1 ){
            while(cur->fwdPtrs[h] && hash > cur->fwdPtrs[h]->hash) {
                cur = cur->fwdPtrs[h]; //step on it
            }
            --h;
        } //while

//same key jumps
        if (cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash) {
            //step on same hash:
             cur = cur->fwdPtrs[2];
            //same hash found, next search for same key
            //cmp = memcmp(key, cur->key, _keyLen);
            int cmp = getCmp(key, cur->key);//key->cmp(cur->key);
            if (cmp < 0) {
                return nullptr; //nothing bigger with same hash
            } else if (0==cmp) {
                return cur;
            }

            while(cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
                //cmp = memcmp(key, cur->fwdPtrs[1]->key, _keyLen);
                cmp = getCmp(key, cur->fwdPtrs[1]->key);// key->cmp(cur->fwdPtrs[1]->key);
                if (cmp < 0) {
                    //found who bigger
                    break;
                }
                if (0==cmp) {
                    return cur->fwdPtrs[1];
                }
                cur = cur->fwdPtrs[1]; //step on it
            }

            while(cur->fwdPtrs[0] && hash==cur->fwdPtrs[0]->hash) {
                cmp = getCmp(key, cur->fwdPtrs[0]->key);// key->cmp(cur->fwdPtrs[0]->key);
                if (cmp < 0) {
                    //found who bigger
                    return nullptr;
                }
                if (0==cmp) {
                    return cur->fwdPtrs[0];
                }
                cur = cur->fwdPtrs[0]; //step on it
            }
        }

        return nullptr;
    } //find


    /*
     * return:
     * 0 ==node with equal key if found
     * 3 == updatePath to insert node with new hash
     * 1 == updatePath to insert node with same hash
     * -N == node with same hash but bigger, to replace at place
   */
    int setll(const unsigned long long hash,
                   TKey const * key,
                   const unsigned short basketID) {
        TONode * cur = &(baskets[basketID]);
        //TONode * curBigger = nullptr;
       // int cmp = 1; //not %found
//same hash jumps
//        for(int h = cur->curHeight; h>1; --h){
//            //At first head->fwdPtrs[h] all nullptr, so not pass:
//            while(cmp != 0 && cur->fwdPtrs[h]!=curBigger) {
//                cmp = hash - cur->fwdPtrs[h]->hash;
//                if (cmp < 0) {
//                    //found who bigger
//                    //next iter will shoot on lower level and skip the same..
//                    curBigger = cur->fwdPtrs[h];
//                    break;
//                }
//                cur = cur->fwdPtrs[h]; //step on it
//            }
//            updatePathOut[h] = cur;
//        }

        int h = 4;//cur->curHeight;
        while( h>1 ){
            //updatePathOut[h] = cur;
            while(cur->fwdPtrs[h] && hash > cur->fwdPtrs[h]->hash) {
                //updatePathOut[h] = cur;
                cur = cur->fwdPtrs[h]; //step on it
            }
            //Update path always point to node that point to bigger or equal one
            updatePathOut[h] = cur;
            --h;
        } //while


//same key jumps
       // if (0==cmp) {
        if (cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash) {
            //step on same hash:
             cur = cur->fwdPtrs[2];
            //same hash found, next search for same key
            //cmp = memcmp(key, cur->key, _keyLen);
            int cmp = getCmp(key, cur->key);// key->cmp(cur->key);
            if (cmp <= 0) {
                updatePathOut[0] = cur;
                return cmp; //must replace hash head in place
            }

            while(cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
                //cmp = memcmp(key, cur->fwdPtrs[1]->key, _keyLen);
                cmp = getCmp(key, cur->fwdPtrs[1]->key);// key->cmp(cur->fwdPtrs[1]->key);
                if (cmp < 0) {
                    //found who bigger                    
                    //curBigger = cur->fwdPtrs[1];
                    break;
                }
                if (0==cmp) {
                    updatePathOut[0] = cur->fwdPtrs[1];
                    return 0; //must replace
                }
                //updatePathOut[1] = cur;
                cur = cur->fwdPtrs[1]; //step on it
            }
            updatePathOut[1] = cur;


            while(cur->fwdPtrs[0] && hash==cur->fwdPtrs[0]->hash) {
                //cmp = memcmp(key, cur->fwdPtrs[0]->key, _keyLen);
                cmp = getCmp(key, cur->fwdPtrs[0]->key);// key->cmp(cur->fwdPtrs[0]->key);
                if (cmp < 0) {
                    //found who bigger
                    break;
                }
                if (0==cmp) {
                    updatePathOut[0] = cur->fwdPtrs[0];
                    return 0; //must replace
                }
                cur = cur->fwdPtrs[0]; //step on it
            }
            updatePathOut[0] = cur;
            return 1; //base alhorithm==insert on updatePath
        } else {
            updatePathOut[0] = cur;
            updatePathOut[1] = cur;
            return 3; //base alhorithm==insert on updatePath
        }

        return 3;
    }

    void clearNode(TONode & node){
        if (node.data){
            _f_delData(node.data);
        }
    }

    void clearNodes(TONode * nodes, unsigned int toClear){
         for (unsigned int i=0; i<toClear; ++i) {
             clearNode(nodes[i]);
         }
    }


    void delInOtherBacket(TONode * nodeToDel) {
        const unsigned long long hash = nodeToDel->hash;
        TONode * cur = &(baskets[hash % _hash_baskets]);
        TONode * updatePath[SKIPHEIGHT];
       // TONode * tmpN = nullptr;
       // long long cmp = 1; //not %found
        int h = 4;//cur->curHeight;
//same hash jumps

        while( h>1 ){
            updatePath[h] = cur;
            while(cur->fwdPtrs[h] && hash > cur->fwdPtrs[h]->hash) {
                updatePath[h] = cur; //start from head that always smaller              
                cur = cur->fwdPtrs[h]; //step on it 
            }
            --h;
        } //while

        assert(cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash);
        //Step on head of same hash queue:
        //cur = cur->fwdPtrs[2];

        //same key jumps
        while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
            updatePath[1] = cur; //need in case of null==cur->fwdPtrs[1]
            //if (nodeToDel->key->cmp(cur->fwdPtrs[1]->key) <= 0) {
            if (getCmp(nodeToDel->key, cur->fwdPtrs[1]->key) <= 0) {
                break;
            }
            cur = cur->fwdPtrs[1]; //step on it
        }

        //jumps on lvl 0:
        //if (nodeToDel==updatePath[1]->fwdPtrs[1]) {
//        if (nodeToDel==cur->fwdPtrs[1]) {
//            updatePath[0] = cur;
//        } else {
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }
        while (cur->fwdPtrs[0]!=nodeToDel){
            cur = cur->fwdPtrs[0]; //step on it
        }
        updatePath[0] = cur;

        assert (updatePath[0]->fwdPtrs[0]==nodeToDel);
        if (updatePath[2]->fwdPtrs[2]==nodeToDel) {
            //This is the head of hash queue:
            cur = nodeToDel->fwdPtrs[0]; //new head
            for ( h = nodeToDel->curHeight; h>0; --h) {
                if (h>cur->curHeight) {
                    cur->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                }
                nodeToDel->fwdPtrs[h] = cur;
            }
            cur->curHeight = nodeToDel->curHeight;
        }
        for ( h = nodeToDel->curHeight; h>=0; --h) {
            updatePath[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
        }
        return;

//        //old:
//        tmpN = updatePathOut[h+1] ;
//        while (h>=0){
//            //enshure path filled:
//            updatePathOut[h] = tmpN;
//            --h;
//        }

//        //same key jumps
//        if (0==cmp) {
//            if (nodeToDel == cur) {
//                tmpN = cur->fwdPtrs[0];
//                if (tmpN && tmpN->hash == nodeToDel->hash) {
//                    //replace with same height
//                    assert(tmpN->curHeight<2);
//                    h = nodeToDel->curHeight;
//                    while (h > tmpN->curHeight) {
//                        tmpN->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
//                        --h;
//                    }
//                    //for final update paths cycle:
////                    while (h>=0){
////                        nodeToDel->fwdPtrs[h] = tmpN->fwdPtrs[h];
////                        --h;
////                    }
//                    tmpN->curHeight = nodeToDel->curHeight;
//                }
//            } else {
//                //must find it, first jumps on lvl 1:
//                while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
//                    updatePathOut[1] = cur;
//                    cmp = memcmp(nodeToDel->key, cur->fwdPtrs[1]->key, _keyLen);
//                    if (cmp <= 0) {
//                        break;
//                    }
//                    cur = cur->fwdPtrs[1]; //step on it
//                }
//                //jumps on lvl 0:
//                if (0==cmp) {
//                    updatePathOut[0] = updatePathOut[1];
//                } else {
//                    while (cur->fwdPtrs[0]!=nodeToDel){
//                        updatePathOut[0] = cur;
//                        cur = cur->fwdPtrs[0]; //step on it
//                    }
//                }
//            }
//            //final update paths:
//            assert (updatePathOut[0]->fwdPtrs[0]==nodeToDel);
//            for (int h = nodeToDel->curHeight; h>=0; --h) {
//                updatePathOut[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
//            }
//            return;
//        }
//        assert(false);
//        return;
    } //delInOtherBasket

    void delInSameBasket(TONode * nodeToDel) {
        for (int h = 4; h>=0; --h){
            if (nodeToDel==updatePathOut[h]) {
                //worst case - must do repath
                delInSameBasketPathOut(nodeToDel, h);
                return;
            }
            if (nodeToDel==updatePathOut[h]->fwdPtrs[h]) {
                //best case - know where and how to update
                delInSameBasketSuperFast(nodeToDel, h);
                return;
            }
        }
        //not on path == path not affected
         delInSameBasketFast(nodeToDel);
         return;
    }

    void delInSameBasketPathOut(TONode * nodeToDel, int top_h) {
        //Node to del in updatePathOut[h], need path to it for update
        const unsigned long long hash = nodeToDel->hash;
        TONode * updatePath[SKIPHEIGHT];
        int h = 4;
        TONode * cur = &(baskets[hash % _hash_baskets]);
        while(h > top_h){
            cur=updatePath[h] = updatePathOut[h];
            --h;
        }
        //= top_h==4? &(baskets[hash % _hash_baskets]);updatePathOut[top_h];
        while (  h>1 ){
            updatePath[h] = cur;
            while (hash > cur->fwdPtrs[h]->hash) {
                updatePath[h] = cur;
                cur = cur->fwdPtrs[h];
            }
            --h;
        } //while
        assert(1==h);
        assert(cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash);
        //Step on head of same hash queue:
        //cur = cur->fwdPtrs[2];

        //same key jumps
        while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
            updatePath[1] = cur;
            //if (nodeToDel->key->cmp(cur->fwdPtrs[1]->key) <= 0) {
            if (getCmp(nodeToDel->key, cur->fwdPtrs[1]->key) <= 0) {
                break;
            }
            cur = cur->fwdPtrs[1]; //step on it
        }
        //jumps on lvl 0:
//        if (nodeToDel == cur) {
//            updatePath[0] = cur;
//        } else {
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }

        while (cur->fwdPtrs[0]!=nodeToDel){
            cur = cur->fwdPtrs[0]; //step on it
        }
        updatePath[0] = cur;

            //final update paths:
            assert (updatePath[0]->fwdPtrs[0]==nodeToDel);
            if (updatePath[2]->fwdPtrs[2]==nodeToDel) {
                //This is the head of hash queue:
                cur = nodeToDel->fwdPtrs[0]; //new head
                for ( h = nodeToDel->curHeight; h>0; --h) {
                    if (h>cur->curHeight) {
                        cur->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                    }
                    nodeToDel->fwdPtrs[h] = cur;
                }
                cur->curHeight = nodeToDel->curHeight;
            }
            for ( h = top_h; h>=0; --h) {
                updatePath[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                //replace deleted node with previos:
                if (nodeToDel==updatePathOut[h]) {
                    updatePathOut[h] = updatePath[h];
                }
            }
            return;
    }//delInSameBasketPathOut

    void delInSameBasketSuperFast(TONode * nodeToDel, int top_h) {
        //need path before to update pointers
        const unsigned long long hash = nodeToDel->hash;
       // long long cmp = 1;
        TONode * updatePath[SKIPHEIGHT];
        updatePath[top_h] = updatePathOut[top_h];
        TONode * cur = updatePathOut[top_h];
        int h = top_h - 1;
        //updatePath[h] = updatePathOut[top_h];
        while (  h>1 ){
            assert(updatePathOut[h]->fwdPtrs[h]->hash<=hash);
            if (cur->hash < updatePathOut[h]->hash) {
                cur = updatePathOut[h];
            }
            updatePath[h] = cur;
            while (cur->fwdPtrs[h] && hash > cur->fwdPtrs[h]->hash) {
                updatePath[h] = cur;
                cur = cur->fwdPtrs[h];
            }
            --h;
        } //while
        assert(1==h);
        //lvl[2] always point to the head of same hash queue:
        assert(cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash);
        //Step on head of same hash queue:
       // cur = cur->fwdPtrs[2];

        //Use all known info to narrow jump:
//        if (updatePathOut[1]->fwdPtrs[1]->hash==hash
//                && cur->fwdPtrs[2]->key->cmp(updatePathOut[1]->fwdPtrs[1]->key) < 0) {
//            cur = updatePathOut[1];
//        }

        //same key jumps
        //updatePath[1] = cur;
        while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
            updatePath[1] = cur;
            //cmp = memcmp(nodeToDel->key, cur->fwdPtrs[1]->key, _keyLen);
//            cmp = nodeToDel->key->cmp(cur->fwdPtrs[1]->key);
//            if (cmp <= 0) {
//                break;
//            }
            //if (nodeToDel->key->cmp(cur->fwdPtrs[1]->key) <= 0) {
            if (getCmp(nodeToDel->key, cur->fwdPtrs[1]->key) <= 0) {
                break;
            }
            cur = cur->fwdPtrs[1]; //step on it
        }
        //jumps on lvl 0:
        //if (0==cmp) {
//        if (nodeToDel==cur->fwdPtrs[0]) {
//            updatePath[0] = cur;
//        } else {
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }

        while (cur->fwdPtrs[0]!=nodeToDel){
            cur = cur->fwdPtrs[0]; //step on it
        }
        updatePath[0] = cur;

//        if (nodeToDel==cur->fwdPtrs[0]) {
//            updatePath[0] = cur;
//        } else {
//            //Use all known info to narrow jump:
//            if (updatePathOut[0]->fwdPtrs[0]->hash==hash
//                    && cur->fwdPtrs[0]->key->cmp(updatePathOut[0]->fwdPtrs[0]->key) < 0) {
//                cur = updatePathOut[0];
//            }
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }

            //final update paths:
            assert (updatePath[0]->fwdPtrs[0]==nodeToDel);
            if (updatePath[2]->fwdPtrs[2]==nodeToDel) {
                //This is the head of hash queue:
                cur = nodeToDel->fwdPtrs[0]; //new head
                for ( h = nodeToDel->curHeight; h>0; --h) {
                    if (h>cur->curHeight) {
                        cur->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                    }
                    nodeToDel->fwdPtrs[h] = cur;
                }
                cur->curHeight = nodeToDel->curHeight;
            }
            for ( h = top_h; h>=0; --h) {
                updatePath[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
            }


            return;

    }//delInSameBasketSuperFast

    void delInSameBasketFast(TONode * nodeToDel) {
        const unsigned long long hash = nodeToDel->hash;
        //TONode * head = &(baskets[hash % _hash_baskets]);
        //TONode * tmpN = nullptr;
        //long long cmp = 1; //not %found
        TONode * updatePath[SKIPHEIGHT];
        int h = 4;
        //updatePathOut filled with previos setll
        //see if it usefull for this proc:
//        while (h>=0) {
//            updatePath[h] = updatePathOut[h]->hash<=hash?updatePathOut[h]:head;
//            head = updatePath[h];
//            --h;
//        }
//        h = 4;

        TONode * cur = &(baskets[hash % _hash_baskets]);
        //while( 0!=cmp && h>1 ){
        while( h>1 ){
//            while(0!=cmp && cur->fwdPtrs[h]) {
//                updatePath[h] = cur; //start from head that always smaller
//                cmp = hash - cur->fwdPtrs[h]->hash;
//                if (cmp < 0) {
//                //found who bigger
//                //next iter will shoot on lower level and skip the same..
//                //    curBigger = cur->fwdPtrs[h];
//                    break;
//                }
//                cur = cur->fwdPtrs[h]; //step on it
//            }
            //updatePath[h] = cur;
//            if (cur->hash<updatePath[h]->hash) {
//                cur = updatePath[h];
//            }

            //Use all known info to narrow jump:
            if (updatePathOut[h]->hash<=hash
                    && cur->hash < updatePathOut[h]->hash) {
                cur = updatePathOut[h];
            }

            updatePath[h] = cur;
            while (cur->fwdPtrs[h] && hash > cur->fwdPtrs[h]->hash) {
                updatePath[h] = cur;
                cur = cur->fwdPtrs[h];
            }
            //updatePath[h] = cur;
            assert(nodeToDel->curHeight<h || updatePath[h]->fwdPtrs[h]->hash==nodeToDel->hash);
            --h;

        } //while

//        tmpN = updatePath[h+1] ;
//        while (h>=0){
//            //enshure path filled with last jump:
//            updatePath[h] = tmpN;
//            --h;
//        }
        assert(cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash);
        //Step on head of same hash queue:
        //cur = cur->fwdPtrs[2];

        //Use all known info to narrow jump:
//        if (updatePathOut[1]->fwdPtrs[1]->hash==hash
//                && cur->fwdPtrs[2]->key->cmp(updatePathOut[1]->fwdPtrs[1]->key) < 0) {
//            cur = updatePathOut[1];
//        }

        //same key jumps
        updatePath[1] = cur; //need in case of null==cur->fwdPtrs[1]
        while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
            updatePath[1] = cur;
            //if (nodeToDel->key->cmp(cur->fwdPtrs[1]->key) <= 0) {
            if (getCmp(nodeToDel->key, cur->fwdPtrs[1]->key) <= 0) {
                break;
            }
            cur = cur->fwdPtrs[1]; //step on it
        }
        //updatePath[1] = cur;
        //jumps on lvl 0:
        //if (nodeToDel==updatePath[1]->fwdPtrs[1]) {
//        if (nodeToDel==cur->fwdPtrs[0]) {
//            updatePath[0] = cur;
//        } else {
//            //Use all known info to narrow jump:
//            if (updatePathOut[0]->fwdPtrs[0]->hash==hash
//                    && cur->fwdPtrs[0]->key->cmp(updatePathOut[0]->fwdPtrs[0]->key) < 0) {
//                cur = updatePathOut[0];
//            }
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }

        while (cur->fwdPtrs[0]!=nodeToDel){
            cur = cur->fwdPtrs[0]; //step on it
        }
        updatePath[0] = cur;

//       // if (0==cmp) {
//            if (nodeToDel == cur) {
//                //found what to del, and this is hash head => must create new hash head
//                tmpN = cur->fwdPtrs[0];
//                if (tmpN && tmpN->hash == nodeToDel->hash) {
//                    //replace with same height
//                    assert(tmpN->curHeight<2);
//                    h = nodeToDel->curHeight;
//                    while (h > tmpN->curHeight) {
//                        tmpN->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
//                        --h;
//                    }
//                    //for final update paths cycle:
////                    while (h>=0){
////                        nodeToDel->fwdPtrs[h] = tmpN->fwdPtrs[h];
////                        --h;
////                    }
//                    tmpN->curHeight = nodeToDel->curHeight;
//                }
//            } else {
//                //must find it, first jumps on lvl 1:
//                while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
//                    updatePath[1] = cur;
//                    //cmp = memcmp(nodeToDel->key, cur->fwdPtrs[1]->key, _keyLen);
//                    cmp = nodeToDel->key->cmp(cur->fwdPtrs[1]->key);
//                    if (cmp <= 0) {
//                        break;
//                    }
//                    cur = cur->fwdPtrs[1]; //step on it
//                }
//                //jumps on lvl 0:
//                if (0==cmp) {
//                    updatePath[0] = updatePath[1];
//                } else {
//                    while (cur->fwdPtrs[0]!=nodeToDel){
//                        updatePath[0] = cur;
//                        cur = cur->fwdPtrs[0]; //step on it
//                    }
//                }
//            }

            //final update paths:
            assert (updatePath[0]->fwdPtrs[0]==nodeToDel);
            if (updatePath[2]->fwdPtrs[2]==nodeToDel) {
                //This is the head of hash queue:
                cur = nodeToDel->fwdPtrs[0]; //new head
                for ( h = nodeToDel->curHeight; h>0; --h) {
                    if (h>cur->curHeight) {
                        cur->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                    }
                    nodeToDel->fwdPtrs[h] = cur;
                }
                cur->curHeight = nodeToDel->curHeight;
            }
            for (h = nodeToDel->curHeight; h>=0; --h) {
                updatePath[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
            }
            return;
//        }
//        assert(false);
//        return;
    }//delInSameBasketFast

    void toTopUsage(TONode * node){
        //Exсlude:
        if (node->mostUseful) {
            node->mostUseful->leastUseful = node->leastUseful;
        }
        if (node->leastUseful) {
            node->leastUseful->mostUseful = node->mostUseful;
        }

        //New leader:
        node->mostUseful = &headNode;
        node->leastUseful = headNode.mostUseful;
        headNode.mostUseful->mostUseful = node;
        if (&headNode==headNode.leastUseful) {
            //The first became last too:
            headNode.leastUseful = node;
        }
        headNode.mostUseful = node;
    }

};

#endif // ONCACHE_H
