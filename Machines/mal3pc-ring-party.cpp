#define FEWER_RINGS

#include "Machines/Rep.hpp"
#include "Protocols/ReplicatedPrep.hpp"
#include "Protocols/Replicated.hpp"
#include "Protocols/Mal3PCShare.h"
#include "Protocols/Mal3PCRingShare.h"

#include "Math/Integer.h"
#include "Processor/RingMachine.hpp"



int main(int argc, const char **argv) {

    HonestMajorityRingMachine<Mal3PCRingShare, Mal3PCShare>(argc, argv);
}