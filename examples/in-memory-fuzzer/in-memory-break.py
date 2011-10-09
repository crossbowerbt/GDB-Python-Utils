#!/usr/local/bin/gdb -P
#
# Utility able to track the functions' parameters of a program
# to individuate possible in-memory-fuzzable points
#
# Usage:
#   ./in-memory-break <program> <arguments...>
#

import subprocess
import re
import sys
import os
import gdb

# import gdb_utils from the current directory
sys.path.append(os.getcwd())
import gdb_utils

#
# Script usage
#
def usage():
    print "Usage:"
    print "\t./in-memory-break.py <program> <arguments...>"
    gdb.execute('quit')

#
# Breakpoint class that prints function arguments
#
class FunctionArgsBreakpoint (gdb.Breakpoint):

    #
    # Initialize the breakpoint
    #
    def __init__ (self, location, name):

        # save address and function name
        self.locstr = location
        self.locname = name

        # clear invalid (relative) names
        if "+0x" in self.locname or "-0x" in self.locname:
            self.locname = "???"

        # exclude library functions
        #if "@plt>" in self.locname:
        #    return

        super (FunctionArgsBreakpoint, self).__init__ (location)

    #
    # Called when the breakpoint is hit
    #
    def stop (self):

        print "Function",self.locname,"at",self.locstr+":"
        
        # read function arguments (linux amd64 calling convention)
        args = list()
        args.append(gdb.parse_and_eval("$rdi"))
        args.append(gdb.parse_and_eval("$rsi"))
        args.append(gdb.parse_and_eval("$rdx"))
        args.append(gdb.parse_and_eval("$rcx"))
        args.append(gdb.parse_and_eval("$r8"))
        args.append(gdb.parse_and_eval("$r9"))

        # print arguments
        arg_num = 0
        for arg in args:

            buffer = gdb_utils.read_string(arg, 32)

            if buffer:
                print "\targument"+str(arg_num),"=",arg,'"'+buffer+'"'
            else:
                print "\targument"+str(arg_num),"=",arg

            arg_num += 1

        print ""

        # return False to continue the execution of the program
        return False

#
# Function that dinamically generates breakpoints (using objdump)
#
def generate_breakpoints (program_name):
    
    # get program disassembly via objdump
    insts = gdb_utils.execute_external_output('objdump -d ' + program_name)

    # find calls
    functions = list()
    for inst in insts:

        # the method is simple:
        # we search for callq instructions and read their destination
        if re.search("callq\s+40.+", inst):

            # we need only the function address and the function name 
            func = inst.split(" ")[-2] + " " + inst.split(" ")[-1]
            functions.append(func)

    # delete duplicates and sort breakpoints
    functions = list(set(functions))
    functions.sort()

    # create breakpoints
    for func in functions:
        func = func.split(" ")
        FunctionArgsBreakpoint("*0x"+func[0], func[1])


#
# The execution starts here
#

# fix a little gdb bug (or feature? I don't know...)
sys.argv = gdb_utils.normalized_argv()

# check and get arguments
if len(sys.argv) < 1:
    usage()

program_name = sys.argv[0]
arguments    = sys.argv[1:]

# load executable program
gdb.execute('file ' + program_name)

# initialize
generate_breakpoints(program_name)

print ""

# run with arguments
gdb.execute('r ' + ' '.join(arguments))

gdb.execute('quit')

