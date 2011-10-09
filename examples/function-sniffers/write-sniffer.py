#!/usr/local/bin/gdb -P
#
# This script is a sniffer for the write() library function.
# It can attach to a process and sniff its write() calls...
#
# Usage:
#   ./write-sniffer <process_name or regular_expression>
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
    print "\t./write-sniffer <process_name or regular_expression>"
    gdb.execute('quit')

#
# Breakpoint class that sniff the write() function
#
class WriteSnifferBreakpoint (gdb.Breakpoint):

    #
    # Initialize the breakpoint
    #
    def __init__ (self):
        super (WriteSnifferBreakpoint, self).__init__ ('write')

    #
    # Called when the breakpoint is hit
    #
    def stop (self):

        # get the string lenght, from the return value of the function
        lenght = gdb.parse_and_eval('$rax')

        # get the string address, from the second arguments of the function
        address = gdb.parse_and_eval('$rsi')

        # get the string
        string = gdb.inferiors()[0].read_memory(address, lenght)

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
WriteSnifferBreakpoint()

# run and sniff...
gdb.execute('continue')

gdb.execute('detach')
gdb.execute('quit')

