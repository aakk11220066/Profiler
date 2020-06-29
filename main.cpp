#include <iostream>
#include <string.h>
#include <map>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <exception>

//TODO: if syscalls fail (including ptrace) neex to immediately exit
//TODO: catch other types of registers as well (e.g. ax, al, bx, eax,...)

namespace ProfilerExceptions{
    class ProfilerException : public std::exception{};
    class NotARegister : public ProfilerException{};
}

typedef unsigned long long int registerContent;

/*enum register_enum{
    RAX,
    RBX,
    RCX,
    RDX,
    RBP,
    RSP,
    RSI,
    RDI,

    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15
};

//parses a string to a register_enum
register_enum stringToRegisterNum(const std::string& strRegister);
*/

//get input from user, return a mapping of (variable name, r name)
std::map<std::string, std::string> getRegisterMap();

//inserts debug interrupt at requested address
//returns overwritten byte
char insertBreakpoint(void* breakpointAddress, pid_t debuggee);

//1. restores overwritten byte to original placement
//2. backs up rip by one instruction (one byte)
//3. runs a single instruction of debuggee
//4. replaces debug interrupt back into breakpointAddress
//5. resumes ordinary run of debuggee
void resumeRun(void* breakpointAddress, char replacedByte, pid_t debuggee);

//1. places trace on self (with ptrace(PTRACE_TRACEME))
//2. execute debuggee program
//3. should wait to begin actual run until told to continue, to allow time for emplacement of breakpoints
void loadDebuggedProgram(const std::string &programPath, const std::string &programCmd);

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
void runDebugger(const std::string &programPath, const std::string &programCmd, void *beginAddress, void *endAddress,
                 const std::map<std::string, std::string> &variableMap);


//------------------------------------------IMPLEMENTATIONS--------------------------
int main(int argc, char* argv[]) {
    std::map<std::string,std::string> variableMap = getRegisterMap(); //mapping of variableName,register name

    //assemble program command
    std::string programCmd = std::string();
    for (int i=3; i<argc; ++i) programCmd += " " + argv[i];

    registerContent beginAddress;
    registerContent endAddress;
    sscanf(argv[1], "%llx", &beginAddress);
    sscanf(argv[2], "%llx", &endAddress);

    runDebugger(argv[3], programCmd, (void *) beginAddress, (void *) endAddress, variableMap);

    return 0;
}

/*
register_enum stringToRegisterNum(const std::string &strRegister) {
    if (!strRegister.compare("rax")) return RAX;
    if (!strRegister.compare("rbx")) return RBX;
    if (!strRegister.compare("rcx")) return RCX;
    if (!strRegister.compare("rdx")) return RDX;
    if (!strRegister.compare("rbp")) return RBP;
    if (!strRegister.compare("rsp")) return RSP;
    if (!strRegister.compare("rsi")) return RSI;
    if (!strRegister.compare("rdi")) return RDI;

    if (!strRegister.compare("r8")) return R8;
    if (!strRegister.compare("r9")) return R9;
    if (!strRegister.compare("r10")) return R10;
    if (!strRegister.compare("r11")) return R11;
    if (!strRegister.compare("r12")) return R12;
    if (!strRegister.compare("r13")) return R13;
    if (!strRegister.compare("r14")) return R14;
    if (!strRegister.compare("r15")) return R15;
    throw ProfilerExceptions::NotARegister();
}
*/

std::map<std::string, std::string> getRegisterMap(){
    std::string variable = std::string();
    std::string strRegister = std::string();
    std::map<std::string,std::string> result; //FIXME: possible bug: may be deleted at end of function

    do{
        std::cin >> variable; //FIXME: may cause a bug by getting deleted at scope end
        std::cin >> strRegister;
        result.insert(std::pair<std::string,std::string>(variable,strRegister));
    } while (variable.compare("run") && strRegister.compare("profile"));
    result.erase("run");

    return result;
}

char insertByte(void *targetAddress, pid_t debuggee, char replacement) {
    //get word that will be overwritten
    long modifiedWord = ptrace(PTRACE_PEEKTEXT, debuggee, targetAddress, nullptr);
    char replacedByte = (char) modifiedWord;

    //replace first byte of word with debug interrupt
    const long debugInterruptCode = replacement;
    const long clearMask = 0xffffff00;
    modifiedWord = (modifiedWord & clearMask) | debugInterruptCode;

    //poketext word in
    ptrace(PTRACE_POKETEXT, debuggee, targetAddress, (void*) &modifiedWord)

    return replacedByte;
}

char insertBreakpoint(void *breakpointAddress, pid_t debuggee) {
    return insertByte(breakpointAddress, debuggee, 0xcc);
}

void resumeRun(void* breakpointAddress, char replacedByte, pid_t debuggee){
    //1. restores overwritten byte to original placement
    insertByte(breakpointAddress, replacedByte, debuggee);

    //2. backs up rip by one instruction (one byte)
    struct user_regs_struct debuggeeRegisters;
    ptrace(PTRACE_GETREGS, debuggee, nullptr, &debuggeeRegisters);
    --debuggeeRegisters.rip;
    //TODO: replace debuggee's registers

    //3. runs a single instruction of debuggee
    ptrace(PTRACE_SINGLESTEP, debuggee, nullptr, nullptr);

    //4. replaces debug interrupt back into breakpointAddress
    insertBreakpoint(breakpointAddress, debuggee);

    //5. resumes ordinary run of debuggee
    ptrace(PTRACE_CONT, debuggee, nullptr, nullptr);
}

//1. places trace on self (with ptrace(PTRACE_TRACEME))
//2. execute debuggee program
//3. should wait to begin actual run until told to continue, to allow time for emplacement of breakpoints
void loadDebuggedProgram(const std::string &programPath, const std::string &programCmd) {
    //1. places trace on self (with ptrace(PTRACE_TRACEME))
    const pid_t SELF = 0;
    ptrace(PTRACE_TRACEME, SELF, nullptr, nullptr);

    //2. execute debuggee program
    execl(programPath.c_str(), programCmd.c_str());

    //3. wait to begin actual run until told to continue, to allow time for emplacement of breakpoints
}

registerContent getVarValueFromUser_regs_struct(const struct user_regs_struct &regs, const std::string &requestedRegister) {
    if (!requestedRegister.compare("rax")) return regs.rax;
    if (!requestedRegister.compare("rbx")) return regs.rbx;
    if (!requestedRegister.compare("rcx")) return regs.rcx;
    if (!requestedRegister.compare("rdx")) return regs.rdx;
    if (!requestedRegister.compare("rbp")) return regs.rbp;
    if (!requestedRegister.compare("rsp")) return regs.rsp;
    if (!requestedRegister.compare("rsi")) return regs.rsi;
    if (!requestedRegister.compare("rdi")) return regs.rdi;

    if (!requestedRegister.compare("r8")) return regs.r8;
    if (!requestedRegister.compare("r9")) return regs.r9;
    if (!requestedRegister.compare("r10")) return regs.r10;
    if (!requestedRegister.compare("r11")) return regs.r11;
    if (!requestedRegister.compare("r12")) return regs.r12;
    if (!requestedRegister.compare("r13")) return regs.r13;
    if (!requestedRegister.compare("r14")) return regs.r14;
    if (!requestedRegister.compare("r15")) return regs.r15;
    throw ProfilerExceptions::NotARegister();
}

//returns values of variables in (currently paused) debugged program
std::map<std::string, registerContent> storeVariables(const std::map<std::string,std::string>& variableMap, pid_t debuggee){
    std::map<std::string, registerContent> variableValues; //FIXME: possible bug: gets deleted at end of function

    struct user_regs_struct debuggeeRegisters;
    ptrace(PTRACE_GETREGS, debuggee, nullptr, &debuggeeRegisters);

    for (const std::pair<std::string, std::string>& mapping : variableMap){
        registerContent varValue = getVarValueFromUser_regs_struct(debuggeeRegisters, mapping.second);
        variableValues.insert(std::pair<std::string, registerContent>(mapping.first, varValue));
    }

    return variableValues;
}


//Informs user (prints to screen) that variable varName changed from oldValue to newValue in inspected code
void printDifference(const std::string& varName, const registerContent oldValue, const registerContent newValue){
    printf("PRF:: %s: %lld->%lld\n", varName.c_str(), oldValue, newValue);
}

//compare data from requested variables with previous data on them, print to user
void compareVariables(
        const std::map<std::string, registerContent>& oldVariableValues,
        const std::map<std::string,std::string>& variableMap,
        pid_t debuggee){

    const std::map<std::string, registerContent> newVariableValues = storeVariables(variableMap, debuggee);

    for (const std::pair<std::string, registerContent>& oldVariable : oldVariableValues){
        const std::pair<std::string, registerContent>& newVariable = newVariableValues[oldVariable.first];
        if (oldVariable.second != newVariable.second){
            printDifference(oldVariable.first, oldVariable.second, newVariable.second);
        }
    }
}

//signals debuggee (who was waiting in step 3 of loadDebuggedProgram for setup to complete) to get started running
void startDebuggeeRun(pid_t debuggee){
    ptrace(PTRACE_CONT, debuggee, nullptr, nullptr);
}

void runDebugger(const std::string &programPath, const std::string &programCmd, void *beginAddress, void *endAddress,
                 const std::map<std::string, std::string> &variableMap) {

    pid_t debuggee;
    if (!(debuggee = fork())) loadDebuggedProgram(programPath, programCmd); //child process that runs debugged program then exits
    //debugger process continues here

    //run debugged process
    char replacedBeginByte = insertBreakpoint(beginAddress, debuggee);
    char replacedEndByte = insertBreakpoint(endAddress, debuggee);
    int debuggeeStatus = 0;

    startDebuggeeRun(debuggee);
    do { //FIXME: possible bug: if debuggee receives a signal during run, will return control to debugger before reached inspected code, and debugger will return no signal (instead of caught signal)
        wait(&debuggeeStatus); //wait for debuggee to reach beginning of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        std::map<std::string, registerContent> storedVariables = storeVariables(variableMap, debuggee);

        resumeRun(beginAddress, replacedBeginByte, debuggee);
        wait(&debuggeeStatus); //wait for debuggee to reach end of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        compareVariables(storedVariables, variableMap, debuggee);
        resumeRun(endAddress, replacedEndByte, debuggee);
    } while (true);
}