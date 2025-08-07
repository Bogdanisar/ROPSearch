#include "Config.hpp"


// Declarations for static members, with default values.

int ROP::Config::MaxInstructionsInInstructionSequence = 10;
bool ROP::Config::SearchForSequencesWithDirectRelativeJumpsInTheMiddle = true;
bool ROP::Config::IgnoreOutputSequencesThatStartWithDirectRelativeJumps = true;
ROP::AssemblySyntax ROP::Config::innerAssemblySyntax = ROP::AssemblySyntax::Intel;
bool ROP::Config::computeRegisterInfo = false;
