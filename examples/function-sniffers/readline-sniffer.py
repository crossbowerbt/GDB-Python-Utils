#!/usr/local/bin/gdb -P
#
# This script is a sniffer for the readline() library function.
# It can attach to a process and sniff its readline() calls...
#
# This script is especially suitable to sniff the commands typed
# in a shell that uses readline(), such as bash. It's just an hint ;)
#
# Usage:
#   ./readline-sniffer <process_name or regular_expression>
#

import gdb

# import gdb_utils from the current directory
sys.path.append(os.getcwd())
import gdb_utils

#
# Script usage
#
def usage():
    print "Usage:"
    print "\t./readline-sniffer <process_name or regular_expression>"
    gdb.execute('quit')

#
# Breakpoint class that sniff the readline() function
#
class ReadlineSnifferBreakpoint (gdb.Breakpoint):

    #
    # Initialize the breakpoint
    #
    def __init__ (self):

        # search the end of the function
        ret_insts = gdb_utils.disassemble_function('readline', 'ret')

        # just use the address of first ret instruction
        ret_addr = ret_insts.keys()[0]

        super (ReadlineSnifferBreakpoint, self).__init__ ('*' + str(ret_addr))

    #
    # Called when the breakpoint is hit
    #
    def stop (self):

        # get the string address, from the return value
        address = gdb.parse_and_eval('$rax')

        # get the string, using gdb_utils.read_string(), since it's null terminated...
        string = gdb_utils.read_string(address, 1024)

        # print sniffed data
        print string
        
        # return False to continue the execution of the program
        return False


#
# The execution starts here
#

# fix a little gdb bug (or feature? I don't know...)
sys.argv = gdb_utils.normalized_argv()

# check and get arguments
if len(sys.argv) < 1:
    usage()

process_name = sys.argv[0]

# get a list of processes that match the given process name
processes = gdb_utils.search_processes(process_name)

# print list and ask for the pid
print 'Processes that match:'
for proc in processes:
    print str(proc['pid']) + ' ' + proc['command']

print ''
print 'Enter the process pid (or just press enter to exit):'
selection = sys.stdin.readline().strip('\r\n ')

if selection == '':
    gdb.execute('quit')

# attach to the selected process
gdb.execute('attach ' + selection)

# generate sniffer breakpoint
ReadlineSnifferBreakpoint()

# run and sniff...
gdb.execute('continue')

gdb.execute('detach')
gdb.execute('quit')

