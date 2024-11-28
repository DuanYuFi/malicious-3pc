#ifndef GC_MAL3PCBINSHARE_H_
#define GC_MAL3PCBINSHARE_H_

#include "MaliciousRepSecret.h"
#include "Protocols/Mal3PCBinProtocol.hpp"

namespace GC {
    class Malicious3PCSecret : public MalRepSecretBase<Malicious3PCSecret>
    {        
        typedef Malicious3PCSecret This;
        typedef MalRepSecretBase<This> super;

    public:
        typedef Mal3PCBinProtocol<This> Protocol;
        typedef SmallMalRepSecret small_type;

        Malicious3PCSecret() {}
        template<class T>
        Malicious3PCSecret(const T& other) : super(other) {}
    };
}

#endif