#include <iostream>
#include <string.h>
#include <map>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <exception>

void myExit(int retVal){
    perror("ptrace");
    exit(retVal);
}

#define C_TRYCATCH(syscall) if ((syscall) < 0) myExit(1)
#define C_CATCHERR(retVal) if (retVal < 0) exit(1)

#define DEFAULT_ERRNO 0

namespace ProfilerExceptions{
    class ProfilerException : public std::exception{};
    class NotARegister : public ProfilerException{};
}

typedef unsigned long long int registerContent;

//get input from user, return a mapping of (variable name, r name)
std::map<std::string, std::string> getRegisterMap();

//tell debuggee to run a single instruction
void singleStep(pid_t debuggee);

//inserts given byte at requested address
//returns overwritten byte
unsigned char insertByte(void *targetAddress, pid_t debuggee, unsigned char replacement);

//inserts debug interrupt at requested address
//returns overwritten byte
unsigned char insertBreakpoint(void* breakpointAddress, pid_t debuggee);

//locally restore debuggee to natural state (without breakpoint)
//1. restores overwritten byte to original placement
//2. backs up rip by one instruction (one byte)
//3. runs a single instruction of debuggee
//4. replaces debug interrupt back into breakpointAddress
void stepPastBreakpoint(void* breakpointAddress, unsigned char replacedByte, pid_t debuggee);

//1. places trace on self (with ptrace(PTRACE_TRACEME))
//2. execute debuggee program
//3. wait to begin actual run until told to continue, to allow time for emplacement of breakpoints
void loadDebuggedProgram(char* programArgs[]);

//Returns the value of a requested register (given by register name) from a user_regs_struct
registerContent getVarValueFromUser_regs_struct(const struct user_regs_struct& regs, const std::string& requestedRegister);

//returns values of variables in (currently paused) debugged program
std::map<std::string, registerContent> storeVariables(const std::map<std::string,std::string>& variableMap, pid_t debuggee);

//Informs user (prints to screen) that variable varName changed from oldValue to newValue in inspected code
void printDifference(const std::string& varName, const registerContent oldValue, const registerContent newValue);

//compare data from requested variables with previous data on them, print to user
void compareVariables(
        const std::map<std::string, registerContent>& oldVariableValues,
        const std::map<std::string,std::string>& variableMap,
        pid_t debuggee);

//signals debuggee (who was waiting in step 3 of loadDebuggedProgram for setup to complete) to get started running
void startDebuggeeRun(pid_t debuggee);

//manage debugging the code
void runDebugger(char *programArgs[], void *beginAddress, void *endAddress,
                 const std::map<std::string, std::string> &variableMap);


//------------------------------------------IMPLEMENTATIONS--------------------------
int main(int argc, char* argv[]) {
    std::map<std::string,std::string> variableMap = getRegisterMap(); //mapping of variableName,register name

    registerContent beginAddress = 0;
    registerContent endAddress = 0;
    if (sscanf(argv[1], "%llx", &beginAddress) == EOF) exit(1);
    if (sscanf(argv[2], "%llx", &endAddress) == EOF) exit(1);

    //note: argv is null-terminated
    runDebugger(argv+3, (void *) beginAddress, (void *) endAddress, variableMap);

    return 0;
}

//get input from user, return a mapping of (variable name, r name)
std::map<std::string, std::string> getRegisterMap(){
    std::string variable = std::string();
    std::string strRegister = std::string();
    std::map<std::string,std::string> result;

    do{
        std::cin >> variable;
        std::cin >> strRegister;
        result.insert(std::pair<std::string,std::string>(variable,strRegister));
    } while (variable.compare("run") && strRegister.compare("profile"));
    result.erase("run");

    return result;
}

//tell debuggee to run a single instruction
void singleStep(pid_t debuggee){
    C_TRYCATCH(ptrace(PTRACE_SINGLESTEP, debuggee, nullptr, nullptr));
    int debugeeSinglestepStatus = 0;
    C_TRYCATCH(wait(&debugeeSinglestepStatus)); //wait for debuggee to return from singlestep
}

//inserts given byte at requested address
//returns overwritten byte
unsigned char insertByte(void *targetAddress, pid_t debuggee, unsigned char replacement) {

    //get word that will be overwritten
    unsigned long modifiedWord = ptrace(PTRACE_PEEKTEXT, debuggee, targetAddress, nullptr);
    if (errno != DEFAULT_ERRNO) C_CATCHERR(modifiedWord);
    unsigned char replacedByte = (unsigned char) modifiedWord;

    //replace first byte of word with debug interrupt
    const unsigned long debugInterruptCode = replacement;
    const unsigned long clearMask = 0xffffffffffffff00;
    modifiedWord = (modifiedWord & clearMask);
    modifiedWord |= debugInterruptCode;

    //poketext word in
    C_TRYCATCH(ptrace(PTRACE_POKETEXT, debuggee, targetAddress, (void*) modifiedWord));

    return replacedByte;
}

//inserts debug interrupt at requested address
//returns overwritten byte
unsigned char insertBreakpoint(void *breakpointAddress, pid_t debuggee) {
    return insertByte(breakpointAddress, debuggee, 0xcc);
}

//locally restore debuggee to natural state (without breakpoint)
//1. restores overwritten byte to original placement
//2. backs up rip by one instruction (one byte)
//3. runs a single instruction of debuggee
//4. replaces debug interrupt back into breakpointAddress
void stepPastBreakpoint(void* breakpointAddress, unsigned char replacedByte, pid_t debuggee){
    pid_t debuggeeCopy = debuggee; //DEBUG
    //1. restores overwritten byte to original placement
    insertByte(breakpointAddress, debuggee, replacedByte);

    //2. backs up rip by one instruction (one byte)
    struct user_regs_struct debuggeeRegisters;
    C_TRYCATCH(ptrace(PTRACE_GETREGS, debuggee, nullptr, &debuggeeRegisters));
    --debuggeeRegisters.rip;
    C_TRYCATCH(ptrace(PTRACE_SETREGS, debuggee, nullptr, &debuggeeRegisters));

    //3. runs a single instruction of debuggee
    singleStep(debuggee);

    //4. replaces debug interrupt back into breakpointAddress
    insertBreakpoint(breakpointAddress, debuggee);
}

//1. places trace on self (with ptrace(PTRACE_TRACEME))
//2. execute debuggee program
//3. wait to begin actual run until told to continue, to allow time for emplacement of breakpoints
void loadDebuggedProgram(char* programArgs[]) {
    //1. places trace on self (with ptrace(PTRACE_TRACEME))
    const pid_t SELF = 0;
    C_TRYCATCH(ptrace(PTRACE_TRACEME, SELF, nullptr, nullptr));

    //2. execute debuggee program
    C_TRYCATCH(execv(programArgs[0], programArgs));

    //3. wait to begin actual run until told to continue, to allow time for emplacement of breakpoints
}

//Returns the value of a requested register (given by register name) from a user_regs_struct
registerContent getVarValueFromUser_regs_struct(const struct user_regs_struct &regs, const std::string &requestedRegister) {
    //64-bit registers
    if (!requestedRegister.compare("rax")) return regs.rax;
    if (!requestedRegister.compare("rbx")) return regs.rbx;
    if (!requestedRegister.compare("rcx")) return regs.rcx;
    if (!requestedRegister.compare("rdx")) return regs.rdx;
    if (!requestedRegister.compare("rsi")) return regs.rsi;

    //32-bit registers
    if (!requestedRegister.compare("eax")) return (unsigned long long int)(unsigned int) regs.rax;
    if (!requestedRegister.compare("ebx")) return (unsigned long long int)(unsigned int) regs.rbx;
    if (!requestedRegister.compare("ecx")) return (unsigned long long int)(unsigned int) regs.rcx;
    if (!requestedRegister.compare("edx")) return (unsigned long long int)(unsigned int) regs.rdx;
    if (!requestedRegister.compare("esi")) return (unsigned long long int)(unsigned int) regs.rsi;

    //16-bit registers
    if (!requestedRegister.compare("ax")) return (unsigned long long int)(unsigned short) regs.rax;
    if (!requestedRegister.compare("bx")) return (unsigned long long int)(unsigned short) regs.rbx;
    if (!requestedRegister.compare("cx")) return (unsigned long long int)(unsigned short) regs.rcx;
    if (!requestedRegister.compare("dx")) return (unsigned long long int)(unsigned short) regs.rdx;
    if (!requestedRegister.compare("si")) return (unsigned long long int)(unsigned short) regs.rsi;

    //8-bit low registers
    if (!requestedRegister.compare("al")) return (unsigned long long int)(unsigned char) regs.rax;
    if (!requestedRegister.compare("bl")) return (unsigned long long int)(unsigned char) regs.rbx;
    if (!requestedRegister.compare("cl")) return (unsigned long long int)(unsigned char) regs.rcx;
    if (!requestedRegister.compare("dl")) return (unsigned long long int)(unsigned char) regs.rdx;
    if (!requestedRegister.compare("sil")) return (unsigned long long int)(unsigned char) regs.rsi;

    //8-bit high registers
    if (!requestedRegister.compare("ah")) return
                ((unsigned long long int)(((unsigned short) regs.rax)) >> 8);
    if (!requestedRegister.compare("bh")) return
                ((unsigned long long int)(((unsigned short) regs.rbx)) >> 8);
    if (!requestedRegister.compare("ch")) return
                ((unsigned long long int)(((unsigned short) regs.rcx)) >> 8);
    if (!requestedRegister.compare("dh")) return
                ((unsigned long long int)(((unsigned short) regs.rdx)) >> 8);
    //not an intel register:
    // if (!requestedRegister.compare("sih")) return
    //      ((unsigned long long int)(((unsigned short) regs.rsi)) >> 8);

    throw ProfilerExceptions::NotARegister();
}

//returns values of variables in (currently paused) debugged program
std::map<std::string, registerContent> storeVariables(const std::map<std::string,std::string>& variableMap, pid_t debuggee){
    std::map<std::string, registerContent> variableValues; //FIXME: possible bug: gets deleted at end of function

    struct user_regs_struct debuggeeRegisters;
    C_TRYCATCH(ptrace(PTRACE_GETREGS, debuggee, nullptr, &debuggeeRegisters));

    for (const std::pair<std::string, std::string>& varToReg_mapping : variableMap){
        registerContent varValue = getVarValueFromUser_regs_struct(debuggeeRegisters, varToReg_mapping.second);
        variableValues.insert(std::pair<std::string, registerContent>(varToReg_mapping.first, varValue));
    }

    return variableValues;
}


//Informs user (prints to screen) that variable varName changed from oldValue to newValue in inspected code
void printDifference(const std::string& varName, const registerContent oldValue, const registerContent newValue){
    C_TRYCATCH(printf("PRF:: %s: %lld->%lld\n", varName.c_str(), oldValue, newValue));
}

//compare data from requested variables with previous data on them, print to user
void compareVariables(
        const std::map<std::string, registerContent>& oldVariableValues,
        const std::map<std::string,std::string>& variableMap,
        pid_t debuggee){

    std::map<std::string, registerContent> newVariableValues = storeVariables(variableMap, debuggee);

    for (const std::pair<std::string, registerContent>& oldVariable : oldVariableValues){
        const registerContent& newValue = newVariableValues[oldVariable.first];
        if (oldVariable.second != newValue){
            printDifference(oldVariable.first, oldVariable.second, newValue);
        }
    }
}

//signals debuggee (who was waiting in step 3 of loadDebuggedProgram for setup to complete) to get started running
void startDebuggeeRun(pid_t debuggee){
    C_TRYCATCH(ptrace(PTRACE_CONT, debuggee, nullptr, nullptr));
}

//manage debugging the code
void runDebugger(char *programArgs[], void *beginAddress, void *endAddress,
                 const std::map<std::string, std::string> &variableMap) {

    pid_t debuggee;
    if (!(debuggee = fork())) loadDebuggedProgram(programArgs); //child process that runs debugged program then exits
    //debugger process continues here

    //run debugged process
    int debuggeeStatus = 0;
    C_TRYCATCH(wait(&debuggeeStatus)); //wait for debuggee to finish loading program
    unsigned char replacedBeginByte = insertBreakpoint(beginAddress, debuggee);
    unsigned char replacedEndByte = insertBreakpoint(endAddress, debuggee);

    startDebuggeeRun(debuggee);
    do { //FIXME: possible bug: if debuggee receives a signal during run, will return control to debugger before reached inspected code, and debugger will return no signal (instead of caught signal)
        C_TRYCATCH(wait(&debuggeeStatus)); //wait for debuggee to reach beginning of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        std::map<std::string, registerContent> storedVariables = storeVariables(variableMap, debuggee);

        stepPastBreakpoint(beginAddress, replacedBeginByte, debuggee);
        C_TRYCATCH(ptrace(PTRACE_CONT, debuggee, nullptr, nullptr)); //resume run

        C_TRYCATCH(wait(&debuggeeStatus)); //wait for debuggee to reach end of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        stepPastBreakpoint(endAddress, replacedEndByte, debuggee);
        compareVariables(storedVariables, variableMap, debuggee);
        C_TRYCATCH(ptrace(PTRACE_CONT, debuggee, nullptr, nullptr)); //resume run
    } while (true);
}