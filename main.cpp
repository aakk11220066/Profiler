#include <iostream>
#include <string.h>
#include <map>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

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
void runDebuggedProgram(const std::string& programName);

//returns values of variables in (currently paused) debugged program
std::map<std::string,char> storeVariables(const std::map<std::string,char>& variableMap, pid_t debuggee);

//compare data from requested variables with previous data on them, print to user
void compareVariables(
        const std::map<std::string,char>& storedVariables,
        const std::map<std::string,char>& variableMap,
        pid_t debuggee);

//signals debuggee (who was waiting in step 3 of runDebuggedProgram for setup to complete) to get started running
void startDebuggeeRun(pid_t debuggee);

void runDebugger(
        const std::string& programName,
        void* beginAddress,
        void* endAddress,
        const std::map<std::string,int>& variableMap){

    pid_t debuggee;
    if (!(debuggee = fork())) runDebuggedProgram(programName); //child process that runs debugged program then exits
    //debugger process continues here

    //run debugged process
    char replacedBeginByte = insertBreakpoint(beginAddress, debuggee);
    char replacedEndByte = insertBreakpoint(endAddress, debuggee);
    int debuggeeStatus = 0;

    startDebuggeeRun(debuggee);
    do {
        wait(&debuggeeStatus); //wait for debuggee to reach beginning of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        std::map<std::string,char> storedVariables = storeVariables(variableMap, debuggee);

        resumeRun(beginAddress, replacedBeginByte, debuggee);
        wait(&debuggeeStatus); //wait for debuggee to reach end of inspected code
        if (WIFEXITED(debuggeeStatus)) break;
        compareVariables(storedVariables, variableMap, debuggee);
        resumeRun(endAddress, replacedEndByte, debuggee);
    } while (true);
}

int main() {
    std::map<std::string,unsigned int> variableMap = getRegisterMapping(); //mapping of variableName,register number

    runDebugger(variableMap);

    return 0;
}