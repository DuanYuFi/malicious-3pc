/*
 * sy-rep-ring-party.cpp
 *
 */

#include "GC/SemiHonestRepPrep.h"
#include "Protocols/MaliciousRepPrep.hpp"
#include "Protocols/SpdzWiseRing.hpp"
#include "Protocols/SpdzWiseMC.h"
#include "Protocols/SpdzWiseRingPrep.h"
#include "Protocols/SpdzWiseInput.h"


#include "Protocols/SwUss23Share.h"
#include "Processor/RingMachine.hpp"
#include "Processor/Data_Files.hpp"
#include "Processor/Instruction.hpp"
#include "Processor/Machine.hpp"
#include "GC/ShareSecret.hpp"
#include "Protocols/SpdzWise.hpp"
#include "Protocols/SpdzWiseRing.hpp"
#include "Protocols/SpdzWisePrep.hpp"
#include "Protocols/SpdzWiseInput.hpp"
#include "Protocols/SpdzWiseShare.hpp"
#include "Protocols/PostSacrifice.hpp"
#include "Protocols/MalRepRingPrep.hpp"
#include "Protocols/MaliciousRepPrep.hpp"
#include "Protocols/RepRingOnlyEdabitPrep.hpp"
#include "Protocols/Share.hpp"
#include "Protocols/SpdzWiseRep3Shuffler.hpp"
#include "Protocols/Rep3Shuffler.hpp"

#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"

int main(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    HonestMajorityRingMachineWithSecurity<SwUss23RingShare, SwUss23FieldShare>(
            argc, argv, opt);
}
