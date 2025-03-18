/*
 * Semi-honest ring protocol
 *
 */

#ifndef PROTOCOLS_BGIN19PROTOCOL_H_
#define PROTOCOLS_BGIN19PROTOCOL_H_

#define USE_MY_MULTIPLICATION

#include "Math/gfp.hpp"
#include "Protocols/Replicated.h"
#include "Protocols/MAC_Check_Base.h"
#include "Processor/Input.h"
#include "Protocols/SemiMC.h"
#include "Tools/random.h"
#include "Utils/dzkp-gf2n.hpp"

#include "Math/gf2nlong.h"

#include <thread>
#include <memory>
#include <mutex>
#include <condition_variable>

#include "Tools/SafeQueue.h"
#include "Tools/my-utils.hpp"

#define USE_SINGLE_THREAD

typedef unsigned __int128 uint128_t;
typedef uint64_t MulRing;
// typedef ExtensionRing<64> gfp0;


#ifndef PRINT_UINT128
#define PRINT_UINT128
void print_uint128(uint128_t x) {
    if (x > 9) print_uint128(x / 10);
    putchar(x % 10 + '0');
}
#endif

#define show_uint128(value) \
    cout << #value << " = "; \
    print_uint128(value); \
    cout << endl;


struct ZKPData {
    ArithDZKProof proof, other_proof, verify_proof;
    ArithVerMsg vermsg, other_vermsg;
    gfp0 **input_left, 
               **input_right, 
               **input_left_next, 
               **input_right_prev, 
               **input_mono_prev, 
               **input_mono_next;
    gfp0** base;
    
    int batch_size, k_size;
    int s;
    

    ZKPData(): input_left(0), input_right(0), input_left_next(0), 
               input_right_prev(0), input_mono_prev(0), input_mono_next(0), base(0) {}
               
    ZKPData(int batch_size, int k_size)
        : batch_size(batch_size), k_size(k_size) {

        int cols = (batch_size - 1) / k_size + 1;

        input_left = new gfp0*[k_size];
        input_right = new gfp0*[k_size];
        input_left_next = new gfp0*[k_size];
        input_right_prev = new gfp0*[k_size];
        input_mono_prev = new gfp0*[k_size];
        input_mono_next = new gfp0*[k_size];

        for (int i = 0; i < k_size; i++) {
            input_left[i] = new gfp0[cols * 2];
            input_right[i] = new gfp0[cols * 2];
            input_right_prev[i] = new gfp0[cols * 2];
            input_left_next[i] = new gfp0[cols * 2];
            input_mono_prev[i] = new gfp0[cols];
            input_mono_next[i] = new gfp0[cols];
        }


        base = new gfp0*[k_size];
        for (int i = 0; i < k_size; i++) {
            base[i] = new gfp0[k_size];
        }

    }

    ~ZKPData() {  

        if (input_left) {
            for (int i = 0; i < k_size; i++) {
                delete[] input_left[i];
                delete[] input_right[i];
                delete[] input_right_prev[i];
                delete[] input_left_next[i];
                delete[] input_mono_prev[i];
                delete[] input_mono_next[i];
                delete[] base[i];
            }
            delete[] input_left;
            delete[] input_right;
            delete[] input_right_prev;
            delete[] input_left_next;
            delete[] input_mono_prev;
            delete[] input_mono_next;
            delete[] base;
        }
    }

    void set(int batch_size, int k_size) {

        if (input_left) {
            for (int i = 0; i < k_size; i++) {
                delete[] input_left[i];
                delete[] input_right[i];
                delete[] input_right_prev[i];
                delete[] input_left_next[i];
                delete[] input_mono_prev[i];
                delete[] input_mono_next[i];
                delete[] base[i];
            }
            delete[] input_left;
            delete[] input_right;
            delete[] input_right_prev;
            delete[] input_left_next;
            delete[] input_mono_prev;
            delete[] input_mono_next;
            delete[] base;
        }

        proof.p_evals_masked.clear();
        other_proof.p_evals_masked.clear();
        verify_proof.p_evals_masked.clear();

        vermsg.b_ss.clear();
        other_vermsg.b_ss.clear();
        
        int cols = (batch_size - 1) / k_size + 1;
        this->batch_size = batch_size;
        this->k_size = k_size;

        input_left = new gfp0*[k_size];
        input_right = new gfp0*[k_size];
        input_left_next = new gfp0*[k_size];
        input_right_prev = new gfp0*[k_size];
        input_mono_prev = new gfp0*[k_size];
        input_mono_next = new gfp0*[k_size];

        for (int i = 0; i < k_size; i++) {
            input_left[i] = new gfp0[cols * 2];
            input_right[i] = new gfp0[cols * 2];
            input_right_prev[i] = new gfp0[cols * 2];
            input_left_next[i] = new gfp0[cols * 2];
            input_mono_prev[i] = new gfp0[cols];
            input_mono_next[i] = new gfp0[cols];
        }


        base = new gfp0*[k_size];
        for (int i = 0; i < k_size; i++) {
            base[i] = new gfp0[k_size];
        }

    }

};

enum ThreadOPCODE {
    
    EXIT = 0,

    PROVE1 = 1,
    PROVE2 = 2,

    VERIFY1 = 11,

    VERIFY = 10

};

typedef pair<ThreadOPCODE, int> ThreadInfo;

template<class T>
class BGIN19Protocol : public ProtocolBase<T>, public ReplicatedBase
{

    typedef ReplicatedBase super;

    typedef array<typename T::value_type, 2> RSShare;

    struct MultiShare {
        RSShare x, y;
        RSShare z;
        RSShare rho;

        MultiShare() {
            x = {0, 0};
            y = {0, 0};
            z = {0, 0};
            rho = {0, 0};
        }
        
        MultiShare(RSShare x, RSShare y, RSShare z, RSShare rho) {
            this->x = x;
            this->y = y;
            this->z = z;
            this->rho = rho;
        }
    };

    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares;
    typename T::clear dotprod_share;

    array<PRNG, 3> global_prngs;
    gfp0 sid;
    ZKPData *zkp_datas;
    int total_zkp_datas, verify_round;
    MultiShare *mul_triples;
    gfp0** thetas;
    gfp0** betas;
    gfp0 **rs_as_prover, **rs_as_verifier1, **rs_as_verifier2;
    octet seed_prove[SEED_SIZE], seed_verify1[SEED_SIZE], seed_verify2[SEED_SIZE];
    SeededPRNG local_prng;

    vector<shared_ptr<thread>> threads;
    WaitSize ws;
    WaitQueue<ThreadInfo> factory;

    int counter1, counter2;
    bool* verify_results;

    const int global_batch_size = OnlineOptions::singleton.batch_size;
    const int global_k_size = OnlineOptions::singleton.k_size;
    const int global_thread_number = OnlineOptions::singleton.thread_number;
    const int global_max_status = OnlineOptions::singleton.max_status;

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

    gfp0* eval_p_poly;
    gfp0* eval_base;
    gfp0** eval_result;
    int verify_flag;

    ofstream *outfile;

public:
    
    static const bool uses_triples = false;

    BGIN19Protocol() {}
    BGIN19Protocol(Player& P);
    BGIN19Protocol(const ReplicatedBase &other) : 
        ReplicatedBase(other)
    {
        
    }

    // Init the protocol
    BGIN19Protocol(const BGIN19Protocol<T> &other) : super(other)
    {
        
    }

    ~BGIN19Protocol() {

        cout << "In destruct" << endl;

        if (zkp_datas == NULL) {
            return ;
        }

        while (counter1 >= global_batch_size * global_max_status) {
            verify_api(global_batch_size * global_max_status);
        }

        if (counter1) {
            verify_api(counter1);
        }

        cout << "Check finish" << endl;

#ifndef USE_SINGLE_THREAD

        for (int i = 0; i < global_thread_number; i ++) {
            factory.push(ThreadInfo(EXIT, -1));
        }

        for (auto &t: threads) {
            if (t->joinable()) {
                t->join();
            }
        }
        
#endif

        delete[] eval_p_poly;
        delete[] eval_base;
        for(int i = 0; i < global_k_size; i++) {
            delete[] eval_result[i];
        }
        delete[] eval_result;  
        delete[] mul_triples;

        for (int i = 0; i < global_max_status; i ++) {
            delete[] thetas[i];
            delete[] betas[i];
        }
        delete[] thetas;
        delete[] betas;

        for (int i = 0; i < global_max_status; i ++) {
            delete[] rs_as_prover[i];
            delete[] rs_as_verifier1[i];
            delete[] rs_as_verifier2[i];
        }

        delete[] rs_as_prover;
        delete[] rs_as_verifier1;
        delete[] rs_as_verifier2;

        delete[] zkp_datas;
        delete[] verify_results;

    }

    void init(Preprocessing<T>& p, typename T::MAC_Check& mc) {
        (void) p;
        (void) mc;
    }


    // Public input.
    static void assign(T& share, const typename T::clear& value, int my_num)
    {
        assert(T::vector_length == 2);
        share.assign_zero();
        if (my_num < 2)
            share[my_num] = value;
    }

    // prepare next round of multiplications
    void init_mul();

    // schedule multiplication
    void prepare_mul(const T&, const T&, int = -1);

    // execute protocol
    void exchange();

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc);

    // return next product
    T finalize_mul(int = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    // void multiply(vector<T>& products, vector<pair<T, T>>& multiplicands,
    //         int begin, int end, SubProcessor<T>& proc);

    T get_random();

    void thread_handler();

    void _PROVE1(int tid);
    void _PROVE2(int tid);
    void prove(int size);
    void prove_single_thread(int size);

    void gen_vermsg();
    void gen_vermsg_single_thread();
    void _VERIFY1(int tid);

    void _VERIFY(int tid);
    bool verify_single_thread();
    bool verify();

    void verify_api(int size);

};

// gfp0 inner_product(gfp0* x, gfp0* y, size_t length) {
//   gfp0 answer = 0;
//   for (size_t i = 0; i < length; ++i) {
//     answer += x[i] * y[i]; 
//   }

//   return answer;
// }

// gfp0 inner_product(gfp0* x, vector<gfp0> y, size_t length) {
//   gfp0 answer = 0;
//   for (size_t i = 0; i < length; ++i) {
//     answer += x[i] * y[i]; 
//   }

//   return answer;
// }

// gfp0 inner_product(gfp0** x, gfp0** y, size_t rows, size_t cols) {
//   gfp0 answer = 0;
//   for (size_t i = 0; i < rows; ++i) {
//     for (size_t j = 0; j < cols; ++j) {
//       answer += x[i][j] * y[i][j];
//     }
//   }

//   return answer;
// }

// gfp0 inner_product(gfp0** x, gfp0* y, size_t rows, size_t cols) {
//   gfp0 answer = 0;
//   for (size_t i = 0; i < rows; ++i) {
//     for (size_t j = 0; j < cols; ++j) {
//       answer += x[i][j] * y[j];
//     }
//   }

//   return answer;
// }

#endif /* PROTOCOLS_BGIN19PROTOCOL_H_ */