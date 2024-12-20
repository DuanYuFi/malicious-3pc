// This is a binary protocol.

#ifndef PROTOCOLS_Mal3PCBINPROTOCOL_HPP_
#define PROTOCOLS_Mal3PCBINPROTOCOL_HPP_

#include "Mal3PCBinProtocol.h"

#include "Replicated.h"
#include "Tools/octetStream.h"
#include "Tools/time-func.h"

#include <chrono>
#include <string.h>
#include <fstream>

template <class T>
Mal3PCBinProtocol<T>::Mal3PCBinProtocol(Player& P) : P(P) {

    cout << "Start Mal3pc at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;

    assert(P.num_players() == 3);
    assert(OnlineOptions::singleton.thread_number > 0);
    assert(OnlineOptions::singleton.max_status > 0);

	if (not P.is_encrypted())
		insecure("unencrypted communication");

    status_queue = new StatusData[OnlineOptions::singleton.max_status];
    
    shared_prngs[0].ReSeed();
	octetStream os;
	os.append(shared_prngs[0].get_seed(), SEED_SIZE);
	P.send_relative(1, os);
	P.receive_relative(-1, os);
	shared_prngs[1].SetSeed(os.get_data());

    os.reset_write_head();
    if (P.my_real_num() == 0) {
        global_prng.ReSeed();
        os.append(global_prng.get_seed(), SEED_SIZE);
        P.send_all(os);
    }
    else {
        P.receive_player(0, os);
        global_prng.SetSeed(os.get_data());
    }
    
    sid = Mersenne::randomize(global_prng);

    check_prngs.resize(OnlineOptions::singleton.max_status);

    for (auto &prngs: check_prngs) {
        prngs[0].SetSeed(shared_prngs[0]);
        prngs[1].SetSeed(shared_prngs[1]);
    }

    for (int i = 0; i < OnlineOptions::singleton.thread_number; i ++) {
        #ifdef TIMING
        check_threads.push_back(std::thread(&Mal3PCBinProtocol<T>::thread_handler, this, i));
        verify_threads.push_back(std::thread(&Mal3PCBinProtocol<T>::verify_thread_handler, this, i));
        #else
        check_threads.push_back(std::thread(&Mal3PCBinProtocol<T>::thread_handler, this));
        verify_threads.push_back(std::thread(&Mal3PCBinProtocol<T>::verify_thread_handler, this));
        #endif
    }

    this->local_counter = 0;
    this->status_counter = 0;
    this->status_pointer = 0;

    wait_size.set_target(OnlineOptions::singleton.max_status);

    idx_input = idx_result = idx_rho = 0;
    // works for binary_batch_size % BLOCK_SIZE = 0
    // share_tuple_block_size = OnlineOptions::singleton.binary_batch_size * OnlineOptions::singleton.max_status * ZOOM_RATE / BLOCK_SIZE; // key bug
    size_t total_batch_size = OnlineOptions::singleton.binary_batch_size * OnlineOptions::singleton.max_status;
    share_tuple_block_size = (MAX_LAYER_SIZE > total_batch_size ? MAX_LAYER_SIZE : total_batch_size) * ZOOM_RATE / BLOCK_SIZE;

    // cout << "Using tuple size: " << share_tuple_block_size << endl;

    share_tuple_blocks = new ShareTupleBlock[share_tuple_block_size];

    vermsgs = new VerMsg[OnlineOptions::singleton.max_status];
}

template <class T>
Mal3PCBinProtocol<T>::Mal3PCBinProtocol(Player& P, array<PRNG, 2>& prngs) :
        P(P)
{
    for (int i = 0; i < 2; i++) {
        shared_prngs[i].SetSeed(prngs[i]);
    }

    for (auto &prngs: check_prngs) {
        prngs[0].SetSeed(shared_prngs[0]);
        prngs[1].SetSeed(shared_prngs[1]);
    }
}

template <class T>
void Mal3PCBinProtocol<T>::check() {

}

template <class T>
void Mal3PCBinProtocol<T>::init_mul()
{
	for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
}

template <class T>
void Mal3PCBinProtocol<T>::finalize_check() {

}

#ifdef TIMING
template <class T>
void Mal3PCBinProtocol<T>::thread_handler(int tid) {
    ofstream outfile;
    outfile.open("logs/Thread_P" + to_string(P.my_real_num()) + "_" + to_string(tid));
    outfile << "thread_handler starts at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;

    auto cp0 = std::chrono::high_resolution_clock::now();
    
    int _ = -1;
    while (true) { 
        if (!cv.pop_dont_stop(_)) {
            continue;
        }

        if (_ == -1) {
            outfile << "breaking thread_handler loop... tid: " << tid << endl;
            
            break;
        }

        outfile << "calling Check_one " << endl;
        Check_one(_);
        
    }
    auto cp1 = std::chrono::high_resolution_clock::now();
    outfile << "thread running time " << (cp1 - cp0).count() / 1e6 << "ms." << endl;
    outfile << "verify_thread_handler ends at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;
    
    return ;
}
#else
template <class T>
void Mal3PCBinProtocol<T>::thread_handler() {

    int _ = -1;
    while (true) { 
        if (!cv.pop_dont_stop(_)) {
            continue;
        }

        if (_ == -1) {            
            break;
        }

        Check_one(_);
    }
    return ;
}
#endif

template <class T>
void Mal3PCBinProtocol<T>::verify_part1(int prev_number, int my_number) {
    DZKProof proof;
    verify_lock.lock();
    int i = verify_index ++;
    proof.unpack(proof_os[1]);
    verify_lock.unlock();

    size_t sz = status_queue[i].sz;

    #ifdef TIMING
    auto cp1 = std::chrono::high_resolution_clock::now();
    #endif

    vermsgs[i] = _gen_vermsg(proof, status_queue[i].node_id, status_queue[i].mask_ss_prev, sz, sid, prev_number, my_number);

    #ifdef TIMING
    auto cp2 = std::chrono::high_resolution_clock::now();
    cout << "Gen_vermsg uses " << (cp2 - cp1).count() / 1e6 << "ms." << endl;
    #endif

    ++ verify_tag;
    
}
template <class T>
void Mal3PCBinProtocol<T>::verify_part2(int next_number, int my_number) {
    
    VerMsg received_vermsg;
    DZKProof proof;
    
    verify_lock.lock();
    received_vermsg.unpack(vermsg_os[1]);
    proof.unpack(proof_os[1]);
    int i = verify_index ++;
    verify_lock.unlock();

    size_t sz = status_queue[i].sz;

    #ifdef TIMING
    auto cp1 = std::chrono::high_resolution_clock::now();
    #endif

    bool res = _verify(proof, received_vermsg, status_queue[i].node_id, status_queue[i].mask_ss_next, sz, sid, next_number, my_number);
    
    #ifdef TIMING
    auto cp2 = std::chrono::high_resolution_clock::now();
    cout << "Verify uses " << (cp2 - cp1).count() / 1e6 << "ms." << endl;
    #endif

    if (!res) {
        check_passed = false;
    }

    ++ verify_tag;
    
}

#ifdef TIMING
template <class T>
void Mal3PCBinProtocol<T>::verify_thread_handler(int tid) {
    ofstream outfile;
    outfile.open("logs/Verify_Thread_P" + to_string(P.my_real_num()) + "_" + to_string(tid));
    outfile << "verify_thread_handler starts at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;

    auto cp0 = std::chrono::high_resolution_clock::now();

    u_char data = 0;
    int my_number = P.my_real_num();
    int prev_number = my_number == 0 ? 2 : my_number - 1;
    int next_number = my_number == 2 ? 0 : my_number + 1;

    while (true) { 
        if (!verify_queue.pop_dont_stop(data)) {
            continue;
        }

        if (data == 0) {
            outfile << "Exit verify thread" << endl;
            break;
        }

        else if (data == 1) {
            outfile << "calling verify_part1" << endl;
            verify_part1(prev_number, my_number);
        }

        else if (data == 2) {
            outfile << "calling verify_part2" << endl;
            verify_part2(next_number, my_number);
        }
    }
    auto cp1 = std::chrono::high_resolution_clock::now();
    outfile << "thread running time " << (cp1 - cp0).count() / 1e6 << "ms." << endl;
    outfile << "verify_thread_handler ends at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;
}
#else
template <class T>
void Mal3PCBinProtocol<T>::verify_thread_handler() {
    u_char data = 0;
    int my_number = P.my_real_num();
    int prev_number = my_number == 0 ? 2 : my_number - 1;
    int next_number = my_number == 2 ? 0 : my_number + 1;

    while (true) { 
        if (!verify_queue.pop_dont_stop(data)) {
            continue;
        }

        if (data == 0) {
            break;
        }

        else if (data == 1) {
            verify_part1(prev_number, my_number);
        }

        else if (data == 2) {
            verify_part2(next_number, my_number);
        }
    }
}
#endif

template <class T>
void Mal3PCBinProtocol<T>::verify() {

    // ofstream outfile;
    // outfile.open("logs/Verify_" + to_string(P.my_real_num()), ios::app);
    
    if (status_counter == 0) {
        return ;
    }

    for (auto& o : proof_os) {
        o.clear();
    }

    for (auto& o : vermsg_os) {
        o.clear();
    }

    size_t size = status_counter;

    // outfile << "Verify with size " << size << endl;

    verify_index = 0;
    verify_tag.reset();
    verify_tag.set_target(size);

    // auto cp0 = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < size; i ++) {
        DZKProof proof = status_queue[i].proof;   
        proof.pack(proof_os[0]);
    }

    // this->check_comm += proof_os[0].get_length();
    P.pass_around(proof_os[0], proof_os[1], 1);

    // auto cp1 = std::chrono::high_resolution_clock::now();
    // outfile << "Exchange proof1 uses " << (cp1 - cp0).count() / 1e6 << "ms." << endl;

    for (size_t i = 0; i < size; i ++) {
        verify_queue.push(1);
    }

    verify_tag.wait();
    verify_tag.reset();
    verify_index = 0;

    // auto cp2 = std::chrono::high_resolution_clock::now();
    // outfile << "Gen vermsg uses " << (cp2 - cp1).count() / 1e6 << "ms." << endl;

    for (size_t i = 0; i < size; i ++) {
        vermsgs[i].pack(vermsg_os[0]);
    }

    proof_os[1].reset_write_head();

    // this->check_comm += proof_os[0].get_length();
    // this->check_comm += vermsg_os[0].get_length();
  
    P.pass_around(proof_os[0], proof_os[1], -1);
    P.pass_around(vermsg_os[0], vermsg_os[1], 1);

    // auto cp3 = std::chrono::high_resolution_clock::now();
    // outfile << "Exchange vermsg uses " << (cp3 - cp2).count() / 1e6 << "ms." << endl;

    for (size_t i = 0; i < size; i ++) {
        verify_queue.push(2);
    }

    verify_tag.wait();

    // auto cp4 = std::chrono::high_resolution_clock::now();
    // outfile << "Verify uses " << (cp4 - cp3).count() / 1e6 << "ms." << endl;

    status_counter = 0;
    wait_size.reset();
}

template <class T>
void Mal3PCBinProtocol<T>::Check_one(size_t node_id, int size) {

    // ofstream outfile;
    // outfile.open("logs/CheckOne_" + to_string(P.my_real_num()), ios::app);

    // outfile << "Entering Check_one, node_id = " << node_id << endl;

    // auto cp0 = std::chrono::high_resolution_clock::now();

    if (size == 0)  return ;
    size_t ms = OnlineOptions::singleton.max_status;

    if (size == -1) size = OnlineOptions::singleton.binary_batch_size;

    size_t sz = size;
    size_t k = OnlineOptions::singleton.k_size;
    size_t k2 = OnlineOptions::singleton.k2_size;
    size_t _T = ((sz - 1) / k + 1) * k;
    size_t s = (_T - 1) / k + 1;
    size_t cnt = log(4 * s) / log(k2) + 3;

    #ifdef DEBUG_OURS_CORRECTNESS_SF
        cout << "cnt in Protocol: " << cnt << endl;
    #endif

    // outfile << "Check one with size " << sz << endl; 

    Field **masks, **mask_ss_next, **mask_ss_prev;

    masks = new Field*[cnt];
    mask_ss_next = new Field*[cnt];
    mask_ss_prev = new Field*[cnt];

    masks[0] = new Field[2 * k - 1];
    mask_ss_next[0] = new Field[2 * k - 1];
    mask_ss_prev[0] = new Field[2 * k - 1];

    
    for (size_t j = 0; j < 2 * k - 1; j ++) {
        mask_ss_next[0][j] = Mersenne::randomize(check_prngs[node_id % ms][1]);
        mask_ss_prev[0][j] = Mersenne::randomize(check_prngs[node_id % ms][0]);
        masks[0][j] = Mersenne::add(mask_ss_next[0][j], mask_ss_prev[0][j]);
    }
        
    for (size_t i = 1; i < cnt; i++) {
        masks[i] = new Field[2 * k2 - 1];
        mask_ss_next[i] = new Field[2 * k2 - 1];
        mask_ss_prev[i] = new Field[2 * k2 - 1];

        for (size_t j = 0; j < 2 * k2 - 1; j ++) {
            mask_ss_next[i][j] = Mersenne::randomize(check_prngs[node_id % ms][1]);
            mask_ss_prev[i][j] = Mersenne::randomize(check_prngs[node_id % ms][0]);
            masks[i][j] = Mersenne::add(mask_ss_next[i][j], mask_ss_prev[i][j]);
        }
    }

    #ifdef TIMING
    auto cp2 = std::chrono::high_resolution_clock::now();
    #endif
    // outfile << "Prepare data uses " << (cp2 - cp1_5).count() / 1e6 << "ms." << endl;

    DZKProof proof = _prove(node_id, masks, sz, sid);

    #ifdef TIMING
    auto cp3 = std::chrono::high_resolution_clock::now();

    // outfile << "Prove uses " << (cp3 - cp2).count() / 1e6 << "ms." << endl;
    cout << "Prove uses " << (cp3 - cp2).count() / 1e6 << "ms." << endl;
    #endif

    // outfile << "in Check_one, pushing status_queue, ID: " << node_id << endl;
    status_queue[node_id % ms] = StatusData(proof,
                                       node_id,
                                       mask_ss_next,
                                       mask_ss_prev,
                                       sz);

    ++wait_size;

    // outfile << "Finish check" << endl;
}


template<class T>
void Mal3PCBinProtocol<T>::prepare_mul(const T& x,
        const T& y, int n)
{
    
    typename T::value_type add_share = x.local_mul(y);

    share_tuple_blocks[idx_input].input1 = ShareTypeBlock(x[0].get(), x[1].get());
    share_tuple_blocks[idx_input].input2 = ShareTypeBlock(y[0].get(), y[1].get());
    idx_input ++;
    if (idx_input == share_tuple_block_size) {
        idx_input = 0;
    }

    prepare_reshare(add_share, n);
    
}

template<class T>
void Mal3PCBinProtocol<T>::prepare_reshare(const typename T::clear& share,
        int n)
{
    typename T::value_type tmp[2];
    for (int i = 0; i < 2; i++) 
        tmp[i].randomize(shared_prngs[i], n);

    share_tuple_blocks[idx_rho].rho = ShareTypeBlock(tmp[0].get(), tmp[1].get());
    idx_rho ++;
    if (idx_rho == share_tuple_block_size) {
        idx_rho = 0;
    }

    auto add_share = share + tmp[0] - tmp[1];
    add_share.pack(os[0], n);
    add_shares.push_back(add_share);
}

template<class T>
void Mal3PCBinProtocol<T>::exchange()
{

    if (os[0].get_length() > 0) {
        // this->exchange_comm += os[0].get_length();
        P.pass_around(os[0], os[1], 1);
    }

    this->rounds++;
}

template<class T>
void Mal3PCBinProtocol<T>::start_exchange()
{
    P.send_relative(1, os[0]);
    // this->exchange_comm += os[0].get_length();
    this->rounds++;
}

template<class T>
void Mal3PCBinProtocol<T>::stop_exchange()
{
    P.receive_relative(-1, os[1]);
}

template<class T>
inline T Mal3PCBinProtocol<T>::finalize_mul(int n)
{
    int this_size = (n == -1 ? T::value_type::length() : n);

    this->counter++;
    this->bit_counter += this_size;

    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

    share_tuple_blocks[idx_result].result = ShareTypeBlock(result[0].get(), result[1].get());

    #ifdef DEBUG_OURS_CORRECTNESS
        // x_i * y_i + z_i + rho_i + rho_{i-1}
        ShareTupleBlock tb = share_tuple_blocks[idx_result];
        long z_res = ((tb.input1.first & (tb.input2.first ^ tb.input2.second)) ^ (tb.input2.first & tb.input1.second)) ^ tb.rho.first ^ tb.rho.second;
        
        cout << "in finalize_mul, z_res: " << z_res << ", z_i: " << tb.result.first << endl;
    #endif

    idx_result ++;
    if (idx_result == share_tuple_block_size) {
        idx_result = 0;
    }
    
    this->local_counter += T::value_type::length(); 
    
    // auto start = std::chrono::high_resolution_clock::now();
    while (local_counter >= (size_t) OnlineOptions::singleton.binary_batch_size) {
        local_counter -= OnlineOptions::singleton.binary_batch_size;     
        
        cv.push(status_pointer);

        status_counter ++;
        status_pointer ++;

        if (status_counter == (size_t) OnlineOptions::singleton.max_status) {
            wait_size.wait();
            verify();
        }
    }
    // auto end = std::chrono::high_resolution_clock::now();
    // cout << "verify uses: " << (end - start).count() / 1e6 << " ms" << endl;
    // cout << "verify() once" << endl;
    
    return result;
}

template <class T>
inline T Mal3PCBinProtocol<T>::dotprod_finalize_mul(int n) {
    this->counter++;
    
    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

    return result;
}

template<class T>
inline void Mal3PCBinProtocol<T>::init_dotprod()
{
    init_mul();
    dotprod_share = 0;
}

template<class T>
inline void Mal3PCBinProtocol<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share = dotprod_share.lazy_add(x.local_mul(y));
}

template<class T>
inline void Mal3PCBinProtocol<T>::next_dotprod()
{
    dotprod_share.normalize();
    prepare_reshare(dotprod_share);
    dotprod_share = 0;
}

template<class T>
inline T Mal3PCBinProtocol<T>::finalize_dotprod(int length)
{

    (void) length;
    this->dot_counter++;
    return dotprod_finalize_mul();
}

template<class T>
T Mal3PCBinProtocol<T>::get_random()
{
    T res;
    for (int i = 0; i < 2; i++)
        res[i].randomize(shared_prngs[i]);
    return res;
}

template<class T>
void Mal3PCBinProtocol<T>::randoms(T& res, int n_bits)
{
    for (int i = 0; i < 2; i++)
        res[i].randomize_part(shared_prngs[i], n_bits);
}

template<class T>
template<class U>
void Mal3PCBinProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        false_type)
{
    assert(regs.size() % 4 == 0);
    assert(proc.P.num_players() == 3);
    assert(proc.Proc != 0);
    typedef typename T::clear value_type;
    int gen_player = 2;
    int comp_player = 1;
    bool generate = P.my_num() == gen_player;
    bool compute = P.my_num() == comp_player;
    ArgList<TruncPrTupleWithGap<value_type>> infos(regs);
    auto& S = proc.get_S();

    octetStream cs;
    ReplicatedInput<T> input(P);

    if (generate)
    {
        SeededPRNG G;
        for (auto info : infos)
            for (int i = 0; i < size; i++)
            {
                auto r = G.get<value_type>();
                input.add_mine(info.upper(r));
                if (info.small_gap())
                    input.add_mine(info.msb(r));
                (r + S[info.source_base + i][0]).pack(cs);
            }
        P.send_to(comp_player, cs);
    }
    else
        input.add_other(gen_player);

    if (compute)
    {
        P.receive_player(gen_player, cs);
        for (auto info : infos)
            for (int i = 0; i < size; i++)
            {
                auto c = cs.get<value_type>() + S[info.source_base + i].sum();
                input.add_mine(info.upper(c));
                if (info.small_gap())
                    input.add_mine(info.msb(c));
            }
    }

    input.add_other(comp_player);
    input.exchange();
    init_mul();

    for (auto info : infos)
        for (int i = 0; i < size; i++)
        {
            this->trunc_pr_counter++;
            auto c_prime = input.finalize(comp_player);
            auto r_prime = input.finalize(gen_player);
            S[info.dest_base + i] = c_prime - r_prime;

            if (info.small_gap())
            {
                auto c_dprime = input.finalize(comp_player);
                auto r_msb = input.finalize(gen_player);
                S[info.dest_base + i] += ((r_msb + c_dprime)
                        << (info.k - info.m));
                prepare_mul(r_msb, c_dprime);
            }
        }

    exchange();

    for (auto info : infos)
        for (int i = 0; i < size; i++)
            if (info.small_gap())
                S[info.dest_base + i] -= finalize_mul()
                        << (info.k - info.m + 1);
}

template<class T>
template<class U>
void Mal3PCBinProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        true_type)
{
    (void) regs, (void) size, (void) proc;
    throw runtime_error("trunc_pr not implemented");
}

template<class T>
template<class U>
void Mal3PCBinProtocol<T>::trunc_pr(const vector<int>& regs, int size,
        U& proc)
{
    this->trunc_rounds++;
    trunc_pr(regs, size, proc, T::clear::characteristic_two);
}

template <class _T>
DZKProof Mal3PCBinProtocol<_T>::_prove(
    size_t node_id,
    Field** masks,
    size_t batch_size, 
    Field sid
) {
    size_t k = OnlineOptions::singleton.k_size; 
    size_t k2 = OnlineOptions::singleton.k2_size;

    vector<vector<Field>> p_evals_masked;
    size_t k_max = k > k2 ? k : k2;
    // Evaluations of polynomial p(X)
    Field* eval_p_poly = new Field[2 * k_max - 1];  

    Field** base = new Field*[k_max - 1];
    for (size_t i = 0; i < k_max - 1; i++) {
        base[i] = new Field[k_max];
    }

    Field** eval_result = new Field*[k_max];
    for(size_t i = 0; i < k_max; i++) {
        eval_result[i] = new Field[k_max];
    }

    Field* eval_base = new Field[k_max];

    // ===============================  First Round  ===============================

    #ifdef TIMING
        auto start = std::chrono::high_resolution_clock::now();
    #endif

    // Vectors of masked evaluations of polynomial p(X)
    size_t T = ((batch_size - 1) / k + 1) * k;
    size_t s = (T - 1) / k + 1;

    // Transcript
    LocalHash<Field> transcript_hash;
    transcript_hash.append_one_msg(sid);


    ShareTupleBlock quarter_k_blocks[k];
    // works for binary_batch_size % BLOCK_SIZE = 0
    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    size_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    size_t cur_quarter_k_blocks_id = 0;
    size_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;
    // assuming k % 4 = 0
    size_t quarter_k = k / 4;

    size_t padded_s = block_cols_num * BLOCK_SIZE;
    s = padded_s;

    for (size_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {

        // fetch k/4 tuple_blocks, containing k / 4 * BLOCKSIZE bit tuples
        if (block_col_id == block_cols_num * 4 - 1 && total_blocks_num - cur_quarter_k_blocks_id < quarter_k) {
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * (total_blocks_num - cur_quarter_k_blocks_id));
            for (size_t i = total_blocks_num - cur_quarter_k_blocks_id ; i < quarter_k; i++)
                quarter_k_blocks[i] = ShareTupleBlock();
        }
        else {
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * quarter_k);
        }
        
        for(size_t i = 0; i < quarter_k; i++) { 

            ShareTupleBlock row_block = quarter_k_blocks[i];
            long a = row_block.input1.first;
            long c = row_block.input2.first;
            long e = (a & c) ^ row_block.result.first ^ row_block.rho.first;
            
            for(size_t j = 0; j < quarter_k; j++) {  

                ShareTupleBlock col_block = quarter_k_blocks[j];
                    
                long b = col_block.input2.second;
                long d = col_block.input1.second;
                long f = col_block.rho.second;

                Field sum1, sum2, sum = 0;
                for(size_t row_entry_id = 0; row_entry_id < 4; row_entry_id++) {
                    for(size_t col_entry_id = 0; col_entry_id < 4; col_entry_id++) {
                    long tmp1 = 0, tmp2, tmp3, tmp4;
                        switch(row_entry_id) {
                            case 0: {
                                switch(col_entry_id) {
                                    // g_1 * h_1 = -2abcd(1-2e)(1-2f) = -2abcd + 4abcde + 4abcdf - 8abcdef
                                    case 0:
                                        tmp1 = a & b & c & d;
                                        break;
                                    // g_1 * h_2 = -2acd(1-2e)(1-2f) = -2acd + 4acde + 4acdf - 8acdef
                                    case 1:
                                        tmp1 = a & c & d;
                                        break;
                                    // g_1 * h_3 = -2abc(1-2e)(1-2f) = -2abc + 4abce + 4abcf - 8abcef
                                    case 2:
                                        tmp1 = a & b & c;
                                        break; 
                                    // g_1 * h_4 = -2ac(1-2e)(1-2f) = -2ac + 4ace + 4acf - 8acef
                                    case 3:
                                        tmp1 = a & c;
                                        break; 
                                } 

                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;

                                sum1 = -2 * (tmp1 >> 32) + 4 * ((tmp2 >> 32) + (tmp3 >> 32)) - 8 * (tmp4 >> 32) + Mersenne::PR;
                                sum2 = -2 * (tmp1 & 0xFFFFFFFF) + 4 * ((tmp2 & 0xFFFFFFFF) + (tmp3 & 0xFFFFFFFF)) - 8 * (tmp4 & 0xFFFFFFFF) + Mersenne::PR;
                                sum = Mersenne::modp(sum1 + sum2);
                                
                                break;
                            }

                            case 1: {
                                switch(col_entry_id) {
                                    // g_2 * h_1 = bcd(1−2e)(1−2f) = bcd - 2bcde - 2bcdf + 4bcdef
                                    case 0:
                                        tmp1 = b & c & d;
                                        break;
                                    // g_2 * h_2 = cd(1−2e)(1−2f) = cd - 2cde - 2cdf + 4cdef
                                    case 1:
                                        tmp1 = c & d;
                                        break; 
                                    // g_2 * h_3 = bc(1−2e)(1−2f) = bc - 2bce - 2bcf + 4bcef
                                    case 2:
                                        tmp1 = b & c;
                                        break; 
                                    case 3:
                                        // g_2 * h_3 = c(1−2e)(1−2f) = c - 2ce - 2cf + 4cef
                                        tmp1 = c;
                                        break; 
                                } 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;

                                sum1 = (tmp1 >> 32) - 2 * ((tmp2 >> 32) + (tmp3 >> 32)) + 4 * (tmp4 >> 32) + Mersenne::PR;
                                sum2 = (tmp1 & 0xFFFFFFFF) - 2 * ((tmp2 & 0xFFFFFFFF) + (tmp3 & 0xFFFFFFFF)) + 4 * (tmp4 & 0xFFFFFFFF) + Mersenne::PR;
                                sum = Mersenne::modp(sum1 + sum2);
                                
                                break;
                            }

                            case 2: {
                                switch(col_entry_id) {
                                    // g_3 * h_1 = abd(1−2e)(1−2f) = abd - 2abde - 2abdf + 4abdef
                                    case 0:
                                        tmp1 = a & b;
                                        break;
                                    // g_3 * h_2 = ad(1−2e)(1−2f) = ad - 2ade - 2adf + 4adef
                                    case 1:
                                        tmp1 = a & d;
                                        break; 
                                    // g_3 * h_3 = ab(1−2e)(1−2f) = ab - 2abe - 2abf + 4abef
                                    case 2:
                                        tmp1 = a & b;
                                        break; 
                                    // g_3 * h_4 = a(1−2e)(1−2f) = a - 2ae - 2af + 4aef
                                    case 3:
                                        tmp1 = a;
                                        break; 
                                }
                                break; 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;
                               
                                sum1 = (tmp1 >> 32) - 2 * ((tmp2 >> 32) + (tmp3 >> 32)) + 4 * (tmp4 >> 32) + Mersenne::PR;
                                sum2 = (tmp1 & 0xFFFFFFFF) - 2 * ((tmp2 & 0xFFFFFFFF) + (tmp3 & 0xFFFFFFFF)) + 4 * (tmp4 & 0xFFFFFFFF) + Mersenne::PR;
                                sum = Mersenne::modp(sum1 + sum2);
                                
                                break;
                            }
                                
                            case 3: {
                                switch(col_entry_id) {
                                    // g_4 * h_1 = bd(1−2e)(1−2f) * (-1/2) = (-1/2) * bd + bde + bdf - 2bdef
                                    // g_4 * h_1 = bd(1−2e)(1−2f) * (-1/2) = (bd - 2bde - 2bdf + 4bdef) * (-1/2)
                                    case 0:
                                        tmp1 = a & b;
                                        break;
                                    // g_4 * h_2 = d(1−2e)(1−2f) * (-1/2) = (-1/2) * d + de + df - 2def
                                    case 1:
                                        tmp1 = d;
                                        break; 
                                    // g_4 * h_3 = b(1−2e)(1−2f) * (-1/2) = (-1/2) * b + be + bf - 2bef
                                    case 2:
                                        tmp1 = a & b;
                                        break; 
                                    // g_4 * h_4 = (1−2e)(1−2f) * (-1/2) = (-1/2) + e + f - 2ef
                                    case 3:
                                        tmp1 = 1;
                                        break; 
                                } 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;
                                
                                sum1 = (tmp1 >> 32) - 2 * ((tmp2 >> 32) + (tmp3 >> 32)) + 4 * (tmp4 >> 32) + Mersenne::PR;
                                sum2 = (tmp1 & 0xFFFFFFFF) - 2 * ((tmp2 & 0xFFFFFFFF) + (tmp3 & 0xFFFFFFFF)) + 4 * (tmp4 & 0xFFFFFFFF) + Mersenne::PR;
                                sum = Mersenne::mul(neg_two_inverse, Mersenne::modp(sum1 + sum2));

                                break; 
                            }
                        }
                        
                        eval_result[i * 4 + row_entry_id][j * 4 + col_entry_id] = Mersenne::add(eval_result[i * 4 + row_entry_id][j * 4 + col_entry_id], sum);
                    }
                }
            }
        }
        cur_quarter_k_blocks_id += quarter_k;
    }

    for(size_t i = 0; i < k; i++) {
        eval_p_poly[i] = eval_result[i][i];
    }

    for(size_t i = 0; i < k - 1; i++) {
        eval_p_poly[i + k] = 0;
        for(size_t j = 0; j < k; j++) {
            for (size_t l = 0; l < k; l++) {
                eval_p_poly[i + k] = Mersenne::add(eval_p_poly[i + k], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
            }
        }
    }

    #ifdef TIMING
        auto end = std::chrono::high_resolution_clock::now();
        cout << "First round (compute p evals) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    uint16_t cnt = 0;

    vector<Field> ss(2 * k - 1);       
    for(size_t i = 0; i < 2 * k - 1; i++) {           
        ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt][i]);
    }
    p_evals_masked.push_back(ss);

    transcript_hash.append_msges(ss);
    Field r = transcript_hash.get_challenge();

    Lagrange::evaluate_bases(k, r, eval_base);

    s *= 4;
    size_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;

    Field **input_left, **input_right;
    input_left = new Field*[k2];
    input_right = new Field*[k2];

    for(size_t i = 0; i < k2; i++) {
        input_left[i] = new Field[s];
        input_right[i] = new Field[s];
    }

    size_t index = 0;
    cur_quarter_k_blocks_id = 0;

    // new matrix: total size = s * 4 = 80w, number of rows: k2 = 8, number of cols: 80w / 8 = 10w

    // generate two lookup tables
    // size_t bits_num = quarter_k / 2 * 3;

    size_t two_powers;

    size_t table_size = 1 << (quarter_k / 2 * 3);
    Field* input_left_table1 = new Field[table_size]; 
    Field* input_left_table2 = new Field[table_size];
    Field* input_right_table1 = new Field[table_size]; 
    Field* input_right_table2 = new Field[table_size];

    for (size_t i = 0; i < table_size; i++) { 
        // i = 0, ..., 4095, 000000000000, ..., 111111111111, each i represents a combination of the 12 bits e^(4),c^(4),a^(4), ..., e^(1),c^(1),a^(1)
        // 12 bits for e^(4),e^(3),e^(2),e^(1), ..., a^(4),a^(3),a^(2),a^(1)

        uint128_t left_sum1 = 0, left_sum2 = 0, right_sum1 = 0, right_sum2 = 0, tmp;
        size_t id1 = 0, id2 = quarter_k / 2;
        for (size_t j = 0; j < quarter_k / 2; j++) {
            // j = 0, 1, 2, 3
            // (e, c, a) = (bits_num[j * 3 + 2], bits_num[j * 3 + 1], bits_num[j * 3])
            // the same for (f, d, b)
            bool ab = i & (1 << (j * 3));
            bool cd = i & (1 << (j * 3 + 1));
            bool ef = i & (1 << (j * 3 + 2)); 

            left_sum1 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id1]) : 0;
            right_sum1 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
            id1++;

            tmp = cd ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
            left_sum1 += tmp;
            right_sum1 += tmp;
            id1++;

            tmp = ab ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
            left_sum1 += tmp;
            right_sum1 += tmp;
            id1++;

            left_sum1 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id1];
            right_sum1 += ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1];

            left_sum2 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id2]) : 0;
            right_sum2 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
            id2++;

            tmp = cd ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
            left_sum2 += tmp;
            right_sum2 += tmp;
            id2++;
            
            tmp = ab ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
            left_sum2 += tmp;
            right_sum2 += tmp;
            id2++;

            left_sum2 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id2];
            right_sum2 += ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2];
        }
        input_left_table1[i] = Mersenne::modp_128(left_sum1);
        input_left_table2[i] = Mersenne::modp_128(left_sum2);
        input_right_table1[i] = Mersenne::modp_128(right_sum1);
        input_right_table2[i] = Mersenne::modp_128(right_sum2);
    }

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    // Batchsize = 640w, total_blocks_num = 640w/64 = 10w, fetching k/4 = 8 blocks per time, needs 12500 times
    // k = 32, s = 640w/32 = 20w, block_cols_num = 20w/64 = 3125, totally 3125 cols of blocks, 3125 * 4 = 12500

    // 12
    size_t bits_num = quarter_k / 2 * 3;
    long* bit_blocks_left1 = new long[bits_num];
    long* bit_blocks_left2 = new long[bits_num];
    long* bit_blocks_right1 = new long[bits_num];
    long* bit_blocks_right2 = new long[bits_num];

    for (size_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {

        // fetch k/4 tuple_blocks, containing k / 4 * BLOCKSIZE bit tuples
        if (block_col_id == block_cols_num * 4 - 1 && total_blocks_num - cur_quarter_k_blocks_id < quarter_k) {
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * (total_blocks_num - cur_quarter_k_blocks_id));
            for (size_t i = total_blocks_num - cur_quarter_k_blocks_id ; i < quarter_k; i++)
                quarter_k_blocks[i] = ShareTupleBlock();
        }
        else {
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * quarter_k);
        }

        // i = 0, 1, 2, 3
        for (size_t i = 0; i < quarter_k / 2; i++) {
            ShareTupleBlock cur_block = quarter_k_blocks[i];

            bit_blocks_left1[i * 3] = cur_block.input1.first;
            bit_blocks_left1[i * 3 + 1] = cur_block.input2.first;
            bit_blocks_left1[i * 3 + 2] = (cur_block.input1.first & cur_block.input2.first) ^ (cur_block.result.first) ^ (cur_block.rho.first);

            bit_blocks_right1[i * 3] = cur_block.input2.second;
            bit_blocks_right1[i * 3 + 1] = cur_block.input1.second;
            bit_blocks_right1[i * 3 + 2] = cur_block.rho.second;

            cur_block = quarter_k_blocks[i + quarter_k / 2];

            bit_blocks_left2[i * 3] = cur_block.input1.first;
            bit_blocks_left2[i * 3 + 1] = cur_block.input2.first;
            bit_blocks_left2[i * 3 + 2] = (cur_block.input1.first & cur_block.input2.first) ^ (cur_block.result.first) ^ (cur_block.rho.first);

            bit_blocks_right2[i * 3] = cur_block.input2.second;
            bit_blocks_right2[i * 3 + 1] = cur_block.input1.second;
            bit_blocks_right2[i * 3 + 2] = cur_block.rho.second;
        }

        size_t group_num = 5;

        // bit_id = 0,1, ..., 12
        for (size_t bit_id = 0; bit_id < 13; bit_id++) {

            // last group
            if (bit_id == 12) 
                group_num = 4;

            // group_id = 0-4 or 0-3 (for the last group)
            for (size_t group_id = 0; group_id < group_num; group_id++) {

                // bit_id = 0:  overall_bit_id = 0, 13, 26, 39, 52
                // bit_id = 1:  overall_bit_id = 1, 14, 27, 40, 53
                // ......
                // bit_id = 11: overall_bit_id = 11, 24, 37, 50, 63
                // bit_id = 12: overall_bit_id = 12, 25, 38, 51
                size_t overall_bit_id = group_id * 13 + bit_id;
                size_t cur_index = index + overall_bit_id;
                size_t row = cur_index / s;
                size_t col = cur_index % s;

                if (cur_index >= s0) {
                    if (row >= k2)
                        break;
                    else {
                        input_left[row][col] = input_right[row][col] = 0;
                        continue;
                    }
                }

                size_t left_id1 = 0, left_id2 = 0, right_id1 = 0, right_id2 = 0;

                for (size_t j = 0; j < bits_num; j++) {
                    left_id1 ^= ((bit_blocks_left1[j] >> overall_bit_id) << j);
                    left_id2 ^= ((bit_blocks_left2[j] >> overall_bit_id) << j);
                    right_id1 ^= ((bit_blocks_right1[j] >> overall_bit_id) << j);
                    right_id2 ^= ((bit_blocks_right2[j] >> overall_bit_id) << j);
                }

                // bit index in the 32-bit integer number, representing 2^(overall_bit_id % 32)
                two_powers = (uint64_t)1 << (overall_bit_id % 32);
                input_left[row][col] = Mersenne::mul(Mersenne::add(input_left_table1[left_id1 & 0xC], input_left_table2[left_id2 & 0xC]), two_powers);
                input_right[row][col] = Mersenne::mul(Mersenne::add(input_right_table1[right_id1 & 0xC], input_right_table2[right_id2 & 0xC]), two_powers);   
            }
        }

        index += BLOCK_SIZE;
        cur_quarter_k_blocks_id += quarter_k;
    }

    cnt++;

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "First round (compute new inputs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    Lagrange::get_bases(k2, base);

    while(true){
        for(size_t i = 0; i < k2; i++) {
            for(size_t j = 0; j < k2; j++) {
                eval_result[i][j] = Mersenne::inner_product(input_left[i], input_right[j], s);
            }
        }

        for(size_t i = 0; i < k2; i++) {
            eval_p_poly[i] = eval_result[i][i];
        }

        for(size_t i = 0; i < k2 - 1; i++) {
            eval_p_poly[i + k2] = 0;
            for(size_t j = 0; j < k2; j++) {
                for (size_t l = 0; l < k2; l++) {
                    eval_p_poly[i + k2] = Mersenne::add(eval_p_poly[i + k2], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
                }
            }
        }

        vector<Field> ss(2 * k2 - 1);       
        for(size_t i = 0; i < 2 * k2 - 1; i++) {           
            ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt][i]);
        }
        p_evals_masked.push_back(ss);

        if (s == 1) {
            break;
        }
        
        transcript_hash.append_msges(ss);
        Field r = transcript_hash.get_challenge();

        Lagrange::evaluate_bases(k2, r, eval_base);

        s0 = s;
        s = (s - 1) / k2 + 1;
       
        for(size_t i = 0; i < k2; i++) {
            for(size_t j = 0; j < s; j++) {
                index = i * s + j;

                if (index < s0) {
                    uint128_t temp_result = 0;
                    for(size_t l = 0; l < k2; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_left[l][index]);
                    }
                    input_left[i][j] = Mersenne::modp_128(temp_result);

                    temp_result = 0;
                    for(size_t l = 0; l < k2; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_right[l][index]);
                    }
                    input_right[i][j] = Mersenne::modp_128(temp_result);

                }
                else {
                    input_left[i][j] = 0;
                    input_right[i][j] = 0;
                }
            }
        }
        cnt++;
    }

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "Recursion uses: " << (end - start).count() / 1e6 << " ms" << endl;
    #endif

    for(size_t i = 0; i < k; i++) {
        delete[] eval_result[i];
    }
    delete[] eval_result;
    delete[] eval_p_poly;

    for (size_t i = 0; i < k - 1; i++) {
        delete[] base[i];
    }
    delete[] base;
    delete[] eval_base;

    for(size_t i = 0; i < k; i++) {
        delete[] input_left[i];
        delete[] input_right[i];
    }

    delete[] input_left;
    delete[] input_right;

    for (size_t j = 0; j < cnt; j ++) {
        delete[] masks[j];
    }
    delete[] masks;

    DZKProof proof = {
        p_evals_masked,
    };
    return proof;
}

template <class _T>
VerMsg Mal3PCBinProtocol<_T>::_gen_vermsg(
    DZKProof proof, 
    size_t node_id,
    Field** masks_ss,
    size_t batch_size, 
    Field sid,
    size_t prover_ID,
    size_t party_ID
) {
    size_t k = OnlineOptions::singleton.k_size;
    size_t k2 = OnlineOptions::singleton.k2_size;

    size_t k_max = k > k2 ? k : k2;

    Field* eval_base = new Field[k_max];
    Field* eval_base_2k = new Field[2 * k_max - 1];    

    // ===============================  First Round  ===============================

    size_t T = ((batch_size - 1) / k + 1) * k;
    size_t s = (T - 1) / k + 1;
    size_t len = log(4 * s) / log(k2) + 2;
    size_t quarter_k = k / 4;

    vector<Field> b_ss(len);
    Field final_input = 0, final_result_ss = 0;

    size_t cnt = 0;

    // Transcript
    LocalHash<Field> transcript_hash;
    transcript_hash.append_one_msg(sid);

    transcript_hash.append_msges(proof.p_evals_masked[cnt]);

    Field out_ss = 0, sum_ss = 0;

    // recover proof
    // two 32-bit integers per 64 bits
    size_t two_powers = ((unsigned long)0xFFFFFFFF - 1) * 2;

    bool prev_party = ((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0;

    if (prev_party) {
        out_ss = Mersenne::mul(neg_two_inverse, two_powers * batch_size);
        for(size_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
        } 
    } else {
        out_ss = 0;
        for(size_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
        }
    }

    // compute random linear combination on the first k outputs using betas
    for (size_t j = 0; j < k; j++) { 
        sum_ss += proof.p_evals_masked[cnt][j];
    }

    b_ss[cnt] = Mersenne::sub(sum_ss, out_ss);
    
    // new evaluations at random point r
    Field r = transcript_hash.get_challenge();
    Lagrange::evaluate_bases(k, r, eval_base);

    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    size_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    size_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;
    size_t cur_quarter_k_blocks_id = 0;
    ShareTupleBlock quarter_k_blocks[k];

    size_t padded_s = block_cols_num * BLOCK_SIZE;
    s = padded_s;

    s *= 4;
    size_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;
    size_t index = 0;
 
    Field **input = new Field*[k2];
    for(size_t i = 0; i < k2; i++) {
        input[i] = new Field[s];
    }

    cur_quarter_k_blocks_id = 0;

    // generate two lookup tables
    size_t table_size = 1 << (quarter_k / 2 * 3);
    Field* input_table1 = new Field[table_size]; 
    Field* input_table2 = new Field[table_size];

    #ifdef TIMING
        auto start = std::chrono::high_resolution_clock::now(), end = start;
    #endif


    if (prev_party) {
        // Right Part
        for (size_t i = 0; i < table_size; i++) { 
            uint128_t sum1 = 0, sum2 = 0;
            size_t id1 = 0, id2 = quarter_k / 2;
            for (size_t j = 0; j < quarter_k / 2; j++) {
                bool ab = i & (1 << (j * 3));
                bool cd = i & (1 << (j * 3 + 1));
                bool ef = i & (1 << (j * 3 + 2));

                sum1 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += cd ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += ab ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1];

                sum2 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += cd ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += ab ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2];
            }
            input_table1[i] = Mersenne::modp_128(sum1);
            input_table2[i] = Mersenne::modp_128(sum2);
        }

        #ifdef TIMING
                end = std::chrono::high_resolution_clock::now();
                cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

                start = std::chrono::high_resolution_clock::now();
        #endif

        size_t bits_num = quarter_k / 2 * 3;
        
        long* bit_blocks_right1 = new long[bits_num];
        long* bit_blocks_right2 = new long[bits_num];

        for (size_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {

            // fetch k/4 tuple_blocks, containing k / 4 * BLOCKSIZE bit tuples
            if (block_col_id == block_cols_num * 4 - 1 && total_blocks_num - cur_quarter_k_blocks_id < quarter_k) {
                memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * (total_blocks_num - cur_quarter_k_blocks_id));
                for (size_t i = total_blocks_num - cur_quarter_k_blocks_id ; i < quarter_k; i++)
                    quarter_k_blocks[i] = ShareTupleBlock();
            }
            else {
                memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * quarter_k);
            }

            // i = 0, 1, 2, 3
            for (size_t i = 0; i < quarter_k / 2; i++) {
                ShareTupleBlock cur_block = quarter_k_blocks[i];

                bit_blocks_right1[i * 3] = cur_block.input2.first;
                bit_blocks_right1[i * 3 + 1] = cur_block.input1.first;
                bit_blocks_right1[i * 3 + 2] = cur_block.rho.first;

                cur_block = quarter_k_blocks[i + quarter_k / 2];

                bit_blocks_right2[i * 3] = cur_block.input2.first;
                bit_blocks_right2[i * 3 + 1] = cur_block.input1.first;
                bit_blocks_right2[i * 3 + 2] = cur_block.rho.first;
            }

            size_t group_num = 5;

            // bit_id = 0,1, ..., 12
            for (size_t bit_id = 0; bit_id < 13; bit_id++) {

                // last group
                if (bit_id == 12) 
                    group_num = 4;

                // group_id = 0-4 or 0-3 (for the last group)
                for (size_t group_id = 0; group_id < group_num; group_id++) {

                    // bit_id = 0:  overall_bit_id = 0, 13, 26, 39, 52
                    // bit_id = 1:  overall_bit_id = 1, 14, 27, 40, 53
                    // ......
                    // bit_id = 11: overall_bit_id = 11, 24, 37, 50, 63
                    // bit_id = 12: overall_bit_id = 12, 25, 38, 51
                    size_t overall_bit_id = group_id * 13 + bit_id;
                    size_t cur_index = index + overall_bit_id;
                    size_t row = cur_index / s;
                    size_t col = cur_index % s;

                    if (cur_index >= s0) {
                        if (row >= k2)
                            break;
                        else {
                            input[row][col] = 0;
                            continue;
                        }
                    }

                    size_t right_id1 = 0, right_id2 = 0;

                    for (size_t j = 0; j < bits_num; j++) {
                        right_id1 ^= ((bit_blocks_right1[j] >> overall_bit_id) << j);
                        right_id2 ^= ((bit_blocks_right2[j] >> overall_bit_id) << j);
                    }

                    two_powers = (uint64_t)1 << (overall_bit_id % 32);
                    input[row][col] = Mersenne::mul(Mersenne::add(input_table1[right_id1 & 0xC], input_table2[right_id2 & 0xC]), two_powers);   
        
                }
            }

            index += BLOCK_SIZE;
            cur_quarter_k_blocks_id += quarter_k;
        }
    }
    else {
        // Left Part
        for (size_t i = 0; i < table_size; i++) { 
            uint128_t sum1 = 0, sum2 = 0;
            size_t id1 = 0, id2 = quarter_k / 2;
            for (size_t j = 0; j < quarter_k / 2; j++) {
                bool ab = i & (1 << (j * 3));
                bool cd = i & (1 << (j * 3 + 1));
                bool ef = i & (1 << (j * 3 + 2));

                sum1 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id1]) : 0;
                id1++;
                sum1 += cd ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += ab ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id1];

                sum2 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id2]) : 0;
                id2++;
                sum2 += cd ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += ab ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id2];
            }
            input_table1[i] = Mersenne::modp_128(sum1);
            input_table2[i] = Mersenne::modp_128(sum2);
        }

        #ifdef TIMING
                end = std::chrono::high_resolution_clock::now();
                cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

                start = std::chrono::high_resolution_clock::now();
        #endif

        size_t bits_num = quarter_k / 2 * 3;

        long* bit_blocks_left1 = new long[bits_num];
        long* bit_blocks_left2 = new long[bits_num];

        for (size_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {

            // fetch k/4 tuple_blocks, containing k / 4 * BLOCKSIZE bit tuples
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * min(quarter_k, total_blocks_num - cur_quarter_k_blocks_id));

            // i = 0, 1, 2, 3
            for (size_t i = 0; i < quarter_k / 2; i++) {
                ShareTupleBlock cur_block = quarter_k_blocks[i];

                bit_blocks_left1[i * 3] = cur_block.input1.second;
                bit_blocks_left1[i * 3 + 1] = cur_block.input2.second;
                bit_blocks_left1[i * 3 + 2] = (cur_block.input1.second & cur_block.input2.second) ^ (cur_block.result.second) ^ (cur_block.rho.second);

                cur_block = quarter_k_blocks[i + quarter_k / 2];

                bit_blocks_left2[i * 3] = cur_block.input1.second;
                bit_blocks_left2[i * 3 + 1] = cur_block.input2.second;
                bit_blocks_left2[i * 3 + 2] = (cur_block.input1.second & cur_block.input2.second) ^ (cur_block.result.second) ^ (cur_block.rho.second);
            }

            size_t group_num = 5;

            // bit_id = 0,1, ..., 12
            for (size_t bit_id = 0; bit_id < 13; bit_id++) {

                // last group
                if (bit_id == 12) 
                    group_num = 4;

                // group_id = 0-4 or 0-3 (for the last group)
                for (size_t group_id = 0; group_id < group_num; group_id++) {

                    // bit_id = 0:  overall_bit_id = 0, 13, 26, 39, 52
                    // bit_id = 1:  overall_bit_id = 1, 14, 27, 40, 53
                    // ......
                    // bit_id = 11: overall_bit_id = 11, 24, 37, 50, 63
                    // bit_id = 12: overall_bit_id = 12, 25, 38, 51
                    size_t overall_bit_id = group_id * 13 + bit_id;
                    size_t cur_index = index + overall_bit_id;
                    size_t row = cur_index / s;
                    size_t col = cur_index % s;

                    if (cur_index >= s0) {
                        if (row >= k2)
                            break;
                        else {
                            input[row][col] = 0;
                            continue;
                        }
                    }

                    size_t left_id1 = 0, left_id2 = 0;

                    for (size_t j = 0; j < bits_num; j++) {
                        left_id1 ^= ((bit_blocks_left1[j] >> overall_bit_id) << j);
                        left_id2 ^= ((bit_blocks_left2[j] >> overall_bit_id) << j);
                    }
                    
                    two_powers = (uint64_t)1 << (overall_bit_id % 32);
                    input[row][col] = Mersenne::mul(Mersenne::add(input_table1[left_id1 & 0xC], input_table2[left_id2 & 0xC]), two_powers);   
                }
            }

            index += BLOCK_SIZE;
            cur_quarter_k_blocks_id += quarter_k;
        }
    }

    cnt++;

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "First round (compute new inputs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    while(true)
    {
        transcript_hash.append_msges(proof.p_evals_masked[cnt]);

        if(prev_party) {
            for(size_t i = 0; i < 2 * k2 - 1; i++) { 
                proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
            } 
        } else {
            for(size_t i = 0; i < 2 * k2 - 1; i++) { 
                proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
            }
        }
        sum_ss = 0;
        for(size_t j = 0; j < k2; j++) { 
            sum_ss += proof.p_evals_masked[cnt][j];
        }

        r = transcript_hash.get_challenge();
        Lagrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);
        uint128_t temp_result = 0;
        for(size_t i = 0; i < 2 * k2 - 1; i++) {
            temp_result += (uint128_t)eval_base_2k[i] * (uint128_t)proof.p_evals_masked[cnt][i];
        }
        out_ss = Mersenne::modp_128(temp_result);

        b_ss[cnt] = Mersenne::sub(sum_ss, out_ss);

        if(s == 1) {
            r = transcript_hash.get_challenge();
            Lagrange::evaluate_bases(k2, r, eval_base);
            
            for(size_t i = 0; i < k2; i++) {
                final_input += eval_base[i] * input[i][0];
            }
            Lagrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);

            final_result_ss = Mersenne::inner_product(eval_base_2k, proof.p_evals_masked[cnt], (2 * k2 - 1));

            break;
        }

        Lagrange::evaluate_bases(k2, r, eval_base);
        s0 = s;
        s = (s - 1) / k2 + 1;
        for(size_t i = 0; i < k2; i++) {
            for(size_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    uint128_t temp_result = 0;
                    for(size_t l = 0; l < k2; l++) {
                        temp_result += (uint128_t)eval_base[l] * (uint128_t)input[l][index];
                    }
                    input[i][j] = Mersenne::modp_128(temp_result);
                }
                else {
                    input[i][j] = 0;
                }
            }
        }

        cnt++;
    }

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "Recursion uses: " << (end - start).count() / 1e6 << " ms" << endl;
    #endif

    delete[] eval_base;
    delete[] eval_base_2k;

    delete[] input;

    for (size_t j = 0; j < cnt; j ++) {
        delete[] masks_ss[j];
    }
    delete[] masks_ss;

    VerMsg vermsg(
        b_ss,
        final_input,
        final_result_ss
    );

    return vermsg;
}

template <class _T>
bool Mal3PCBinProtocol<_T>::_verify(
    DZKProof proof, 
    VerMsg other_vermsg, 
    size_t node_id,
    Field** masks_ss,
    size_t batch_size, 
    Field sid,
    size_t prover_ID,
    size_t party_ID
) {
    size_t k = OnlineOptions::singleton.k_size;
    size_t k2 = OnlineOptions::singleton.k2_size;
    
    size_t T = ((batch_size - 1) / k + 1) * k;
    size_t s = (T - 1) / k + 1;
    size_t len = log(4 * s) / log(k2) + 2;
    
    VerMsg self_vermsg = _gen_vermsg(proof, node_id, masks_ss, batch_size, sid, prover_ID, party_ID);

    Field b;
    for(size_t i = 0; i < len; i++) {
        b = Mersenne::add(self_vermsg.b_ss[i], other_vermsg.b_ss[i]);
        
        if(!b) {    
            return false;
        }
    }

    Field res = Mersenne::mul(self_vermsg.final_input, other_vermsg.final_input);
    Field p_eval_r = Mersenne::add(self_vermsg.final_result_ss, other_vermsg.final_result_ss);
    
    Field diff = res - p_eval_r;
    if(!diff) {   
        return false;
    } 

    return true;
}

#endif