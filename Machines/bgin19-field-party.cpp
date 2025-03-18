
#include "Protocols/BGIN19Share.h"
#include "Protocols/BGIN19Protocol.hpp"
#include "Protocols/ReplicatedPrep.hpp"
#include "Machines/Rep.hpp"
#include "Protocols/Replicated.hpp"

#include "Math/Integer.h"
#include "Processor/FieldMachine.hpp"

int main(int argc, const char **argv) {

    gfp0::init_field(2305843009213693951, true);
    HonestMajorityFieldMachine<BGIN19Share>(argc, argv);
}