#!/usr/local/bin/gdb -P
#
# Proof-of-concept implementation of an in-memory-fuzzer
# to individuate bugs in parsing routines
#
# The fuzzer uses process snapshots/restorations, and can be used as a base
# to implement more complex fuzzers...
#
# Usage:
#   ./in-memory-fuzz <function to fuzz> <program> <arguments...>
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
    print "\t./in-memory-fuzz.py <function to fuzz> <program> <arguments...>"
    print "Examples:"
    print "\t./in-memory-fuzz.py parse getdomain test@email.com"
    print "\t./in-memory-fuzz.py *0x40064d getdomain test@email.com"
    gdb.execute('quit')

#
# Allocate memory on debugged process heap
#
def malloc(size):
    output = gdb_utils.execute_output('call malloc(' + str(size) + ')')
    # return memory address
    return int(output[0].split(' ')[2])

#
# Generate strings for the fuzzer
#
# In this case we start with a short email and slowly increase its length...
#
fuzz_email = ''
def get_fuzz_email():
    global fuzz_email

    if fuzz_email == '':
        fuzz_email = 'test@email.com' # start case
    else:
        fuzz_email += 'A'             # append an 'A' to the email

    return fuzz_email

#
# The execution starts here
#

# fix a little gdb bug (or feature? I don't know...)
sys.argv = gdb_utils.normalized_argv()

# check and get arguments
if len(sys.argv) < 2:
    usage()

brk_function = sys.argv[0]
program_name = sys.argv[1]
arguments    = sys.argv[2:]

# load executable program
gdb.execute('file ' + program_name)

# set shapshot breakpoint
gdb.execute('break ' + brk_function)

# run with arguments
gdb.execute('r ' + ' '.join(arguments))

#
# The execution has now reached the breakpoint
#

# fuzzing loop (with snapshot/restore)
i = 1
while True:
    print 'fuzz loop: ' + str(i)
    i +=1

    # we take the snapshot with the command 'checkpoint' (GDB >= 7.0)
    gdb.execute('checkpoint')

    # get the current fuzz string (and null terminate it)
    fuzz_string = get_fuzz_email() + '\0'

    # if the fuzz string is too long, we end the loop
    if len(fuzz_string) > 65000:
        break

    # allocate the space for the fuzz string on the heap
    fuzz_string_addr = malloc( len(fuzz_string) + 10 )

    # set the register that holds the first argument (amd64 arch) to the address of fuzz_string
    gdb.execute('set $rdi=' + str(fuzz_string_addr))

    # write fuzz_string to that address
    inferior = gdb.inferiors()[0]
    inferior.write_memory(fuzz_string_addr, fuzz_string, len(fuzz_string))

    print 'string len: ' + str(len(fuzz_string))
    gdb.execute("x/s $rdi")

    # continue execution until the end of the function
    gdb.execute('finish')

    # check if the program has crashed
    if gdb_utils.execute_output('info checkpoints')[0] == 'No checkpoints.':
        print ''
        print '#'
        print '# The program has crashed! Stack exhaustion or bug???'
        print '# Now is your turn, have fun! :P'
        print '#'
        print ''
        gdb.execute('quit')

    # restore snapshot
    gdb.execute("restart 1")
    gdb.execute("delete checkpoint 0")

# script ends
print 'No crashes...'
gdb.execute('quit')

