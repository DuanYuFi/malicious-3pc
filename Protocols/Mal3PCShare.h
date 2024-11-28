
#ifndef PROTOCOLS_MAL3PCSHARE_H_
#define PROTOCOLS_MAL3PCSHARE_H_

#include "Math/FixedVec.h"
#include "Math/Integer.h"
#include "Protocols/Replicated.h"
#include "Protocols/Mal3PCArithProtocol.hpp"
#include "GC/ShareSecret.h"
#include "GC/Mal3PCBinShare.h"
#include "ShareInterface.h"
#include "Processor/Instruction.h"

#include "Protocols/Rep3Share.h"

namespace GC {
    class Malicious3PCSecret;
}

template<class T>
class Mal3PCShare : public RepShare<T, 2>
{
    typedef RepShare<T, 2> super;
    typedef Mal3PCShare This;

public:
    typedef T clear;

    typedef Mal3PCArithProtocol<Mal3PCShare> Protocol;
    typedef ReplicatedMC<Mal3PCShare> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef ReplicatedInput<Mal3PCShare> Input;
    typedef ReplicatedPO<This> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef ReplicatedPrep<Mal3PCShare> LivePrep;
    typedef ReplicatedRingPrep<Mal3PCShare> TriplePrep;
    typedef Mal3PCShare Honest;

    typedef Mal3PCShare Scalar;

    typedef GC::Malicious3PCSecret bit_type;

    const static bool needs_ot = false;
    const static bool dishonest_majority = false;
    const static bool expensive = false;
    const static bool variable_players = false;
    static const bool has_trunc_pr = true;
    static const bool malicious = false;
    bool is_zero_share = false;

    static string type_short()
    {
        return "T3" + string(1, clear::type_char());
    }
    static string type_string()
    {
        return "Test " + T::type_string();
    }
    static char type_char()
    {
        return T::type_char();
    }

    static Mal3PCShare constant(T value, int my_num,
            typename super::mac_key_type = {})
    {
        return Mal3PCShare(value, my_num);
    }

    Mal3PCShare()
    {
        // if (BUILDING_SHARE_PROCESS & SEMI3_RING_SHARE_PROCESS) {
        //     cout << "In Mal3PCShare()" << endl;
        // }
    }
    template<class U>
    Mal3PCShare(const U& other) :
            super(other)
    {
        // if (BUILDING_SHARE_PROCESS & SEMI3_RING_SHARE_PROCESS) {
        //     cout << "In Mal3PCShare(const U& other)" << endl;
        // }
    }

    Mal3PCShare(T value, int my_num, const T& alphai = {})
    {

        // if (BUILDING_SHARE_PROCESS & SEMI3_RING_SHARE_PROCESS) {
        //     cout << "In Mal3PCShare(T value, int my_num, const T& alphai = {})" << endl;
        //     cout << "assinging " << value << " to " << my_num << endl;
        // }

        (void) alphai;

        Mal3PCArithProtocol<Mal3PCShare>::assign(*this, value, my_num);
    }

    void assign(const char* buffer)
    {
        // if (BUILDING_SHARE_PROCESS & SEMI3_RING_SHARE_PROCESS) {
        //     cout << "In Mal3PCShare::assign(const char* buffer)" << endl;
        //     cout << "assinging " << buffer << endl;
        // }
        FixedVec<T, 2>::assign(buffer);
    }

    clear local_mul(const Mal3PCShare& other) const
    {
        auto a = (*this)[0].lazy_mul(other.lazy_sum());
        auto b = (*this)[1].lazy_mul(other[0]);
        return a.lazy_add(b);
    }
};

#endif /* PROTOCOLS_Mal3PCShare_H_ */
