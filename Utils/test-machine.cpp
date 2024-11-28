#define FEWER_RINGS

#include "Protocols/Mal3PCShare.h"
#include "Protocols/Mal3PCRingShare.h"
#include "Protocols/ReplicatedPrep.hpp"
#include "Machines/Rep.hpp"
#include "Protocols/Replicated.hpp"

#include "Math/Integer.h"
#include "Processor/RingMachine.hpp"

template <class T>
void test(vector<T> S) {
    (void) S;
}

int main() {
    StackedVector<GC::Malicious3PCSecret> S;
    test(S);

    return 0;
}