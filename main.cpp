#include <iostream>
#include <string.h>
#include <map>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

enum register_enum{
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

//get input from user, return a mapping of (variable name, register number)
std::map<std::string, register_enum> getRegisterMap();

//inserts debug interrupt at requested address
//returns overwritten byte
char insertBreakpoint(void* breakpointAddress, pid_t debuggee);

//starts the debuggee running
void startDebuggeeRun();

//1. restores overwritten byte to original placement
//2. backs up rip by one instruction (one byte)
//3. runs a single instruction of debuggee
//4. replaces debug interrupt back into breakpointAddress
//5. resumes ordinary run of debuggee
void resumeRun(void* breakpointAddress, char replacedByte, pid_t debuggee);

//1. places trace on self (with ptrace(PTRACE_TRACEME))
//2. execute debuggee program
//3. should wait to begin actual run until told to continue to allow time for emplacement of breakpoints
void runDebuggedProgram(const std::string& programCmd);

//returns values of variables in (currently paused) debugged program
std::map<std::string, unsigned long long int> storeVariables(const std::map<std::string,register_enum>& variableMap, pid_t debuggee);

//compare data from requested variables with previous data on them, print to user
void compareVariables(
        const std::map<std::string,unsigned long long int>& storedVariables,
        const std::map<std::string,register_enum>& variableMap,
        pid_t debuggee);

//signals debuggee (who was waiting in step 3 of runDebuggedProgram for setup to complete) to get started running
void startDebuggeeRun(pid_t debuggee);

//manage debugging the code
void runDebugger(
        const std::string& programCmd,
        void* beginAddress,
        void* endAddress,
        const std::map<std::string,int>& variableMap);

int main(int argc, char* argv[]) {
    std::map<std::string,register_enum> variableMap = getRegisterMap(); //mapping of variableName,register number

    //assemble program command
    std::string programCmd = std::string();
    for (int i=3; i<argc; ++i) programCmd += argv[i];

    unsigned long long int beginAddress;
    unsigned long long int endAddress;
    sscanf(argv[1], "%llx", &beginAddress);
    sscanf(argv[2], "%llx", &endAddress);

    runDebugger(programCmd, (void*)beginAddress, (void*)endAddress, variableMap);

    return 0;
}

std::map<std::string, register_enum> getRegisterMap(){
    std::string variable = std::string();
    std::string strRegister = std::string();
    std::map<std::string,register_enum> result;

    do{
        std::cin >> variable;
        std::cin >> strRegister;
        register_enum numRegister = stringToRegisterNum(strRegister);
        result.insert(std::pair<std::string,register_enum>(variable,numRegister));
    } while (variable.compare("run") && strRegister.compare("profile"));
    result.erase("run");

    return result;
}

void runDebugger(
        const std::string& programCmd,
        void* beginAddress,
        void* endAddress,
        const std::map<std::string,register_enum>& variableMap){

    pid_t debuggee;
    if (!(debuggee = fork())) runDebuggedProgram(programCmd); //child process that runs debugged program then exits
    //debugger process continues here

    //run debugged process
    char replacedBeginByte = insertBreakpoint(beginAddress, debuggee);
    char replacedEndByte = insertBreakpoint(endAddress, debuggee);
    int debuggeeStatus = 0;

    startDebuggeeRun(debuggee);
    do {
        wait(&debuggeeStatus); //wait for debuggee to reach beginning of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        std::map<std::string,unsigned long long int> storedVariables = storeVariables(variableMap, debuggee);

        resumeRun(beginAddress, replacedBeginByte, debuggee);
        wait(&debuggeeStatus); //wait for debuggee to reach end of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        compareVariables(storedVariables, variableMap, debuggee);
        resumeRun(endAddress, replacedEndByte, debuggee);
    } while (true);
}