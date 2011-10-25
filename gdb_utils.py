import subprocess
import re
import sys
import os
import gdb

##
# @package gdb_utils
# Various utility functions to work with GDB.
#
# This package provides functions not included in the default gdb module.
#

##
# Read an ASCII string from memory
#
# @param address (int) memory address of the string
# @param count (int) maximum string length
#
# @return string read (str)
#
def read_string(address, count):
    
    try:
        # try to read the string pointed by address
        buffer = gdb.inferiors()[0].read_memory(address, count)

        # determine string length
        i = 0
        while ord(buffer[i]) > 0 and ord(buffer[i]) < 128:
            i += 1

        # terminate and escape buffer
        buffer = buffer[0:i]
        buffer = buffer.replace("\n","\\n").replace("\r","\\r").replace("\t","\\t").replace("\"","\\\"")

        # return buffer
        return buffer

    except:
        # cannot read the string
        return None

##
# Execute a GDB command with output capture
#
# @param command (str) GDB command
#
# @return command output (str)
#
def execute_output(command):
    
    # create temporary file for the output
    filename = os.getenv('HOME') + os.sep + 'gdb_output_' + str(os.getpid())

    # set gdb logging
    gdb.execute("set logging file " + filename)
    gdb.execute("set logging overwrite on")
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")
    
    # execute command
    try:
        gdb.execute(command)
    except:
        pass

    # restore normal gdb behaviour
    gdb.execute("set logging off")
    gdb.execute("set logging redirect off")

    # read output and close temporary file
    outfile = open(filename, 'r')
    output = outfile.read()
    outfile.close()

    # delete file
    os.remove(filename)

    # split lines
    output = output.splitlines()    
    
    return output

##
# Execute external command
#
# @param command (str) command string to execute (command + arguments)
#
def execute_external(command):

    # execute command
    subprocess.call(command, shell=True)

##
# Execute external command with output capture
#
# @param command (str) command string to execute (command + arguments)
#
# @return command output as list of strings
#
def execute_external_output(command):
    
    # execute command and capture output
    ps = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
    (out, err) = ps.communicate()
    output = out.splitlines()

    return output


##
# Search program functions and return their names and addresses
#
# @param regex (str) optional regular expression to search for specific functions
#
# @return dictionary of the type func_name->address
#
def search_functions(regex=''):

    # get the functions
    output = execute_output('info functions ' + regex)
    
    functions = dict()
    deb_funcs = list()
    
    # extract debugging functions
    for line in output:
        if re.search('\);$', line):
            func = line.split('(')[0].split(' ')[-1]
            func = func.replace('*', '')
            deb_funcs.append(func)

    # insert debugging function in dictionary
    for func in deb_funcs:
        addr = execute_output('p ' + func)[0].split(' ')[-2]
        addr = int(addr, 16)
        functions[func] = addr

    # insert non debugging functions in dictionary
    for line in output:
        if re.search('^0x[0-9a-f]+', line):
            func = line.split(' ')[-1]
            addr = line.split(' ')[0]
            addr = int(addr, 16)
            functions[func] = addr

    return functions

##
# Search running processes and return their info
#
# @param regex (str) optional regular expression applied to the process name
#
# @return a list of hash maps, where every hash map contains informations about a process
#
def search_processes(regex=''):

    processes = list()

    # get processes via ps command
    output = execute_external_output('ps auxww')

    # delete first line
    output = output[1:]

    # parse processes info
    for line in output:
        field = re.compile('\s+').split(line)

        # exclude processes that don't match the regexp
        if regex != '':
            if not re.search(regex, field[10]):
                continue

        # add process info to the list
        processes.append({
            'user': field[0],
            'pid': int(field[1]),
            'percentage_cpu': eval(field[2]),
            'percentage_mem': eval(field[3]),
            'vsz': int(field[4]),
            'rss': int(field[5]),
            'tty': field[6],
            'stat': field[7],
            'start': field[8],
            'time': field[9],
            'command': field[10],
            'args': field[11:] if len(field) > 11 else ''
            })

    return processes

##
# Parse disassebled output (internal function)
#
# @param output (list of strings) disassembled output
# @param regex (str) optional regular expression applied to the instruction mnemonic
#
# @return list of instructions represented by a dictionary address->instr_code
#
def parse_disassembled_output(output, regex=''):

    instructions = dict()

    # parse output
    for line in output:

        # delete program counter mark
        line = line.replace('=>', '  ')

        # get only instruction lines
        if line.startswith(' '):
            field = re.compile('\s+').split(line)

            # parse
            if field[1].endswith(':'):
                addr = int(field[1].replace(':',''), 16)
                code = ' '.join(field[2:])
            else:
                addr = int(field[1], 16)
                code = ' '.join(field[3:])

            # apply regex
            if regex != '':
                if not re.search(regex, code):
                    continue

            # add to instructions
            instructions[addr] = code

    return instructions


##
# Disassemble a function
#
# @param func_name (str) name of the function to disassemble
# @param regex (str) optional regular expression applied to the instruction mnemonic
#
# @return list of instructions represented by a dictionary address->instr_code
#
def disassemble_function(func_name, regex=''):
    
    # get disassembled output
    output = execute_output('disassemble ' + func_name)

    # parse and return output
    return parse_disassembled_output(output, regex)


##
# Disassemble a range
#
# @param start (int) start address
# @param end (int) end address
# @param regex (str) optional regular expression applied to the instruction mnemonic
#
# @return list of instructions represented by a dictionary address->instr_code
#
def disassemble_range(start, end, regex=''):

    # get disassembled output
    output = execute_output('disassemble ' + str(start) + ', ' + str(end))

    # parse and return output
    return parse_disassembled_output(output, regex)

##
# Disassemble a variable number of instruction
#
# @param start (int) start address
# @param count (int) total number of instructions to disassemble
# @param regex (str) optional regular expression applied to the instruction mnemonic
#
# @return list of instructions represented by a dictionary address->instr_code
#
def disassemble_count(start, count, regex=''):

    # get disassembled output
    output = execute_output('x/' + str(count) + 'i ' + str(start))

    # parse and return output
    return parse_disassembled_output(output, regex)

##
# Disassemble and return the current instruction (pointed by the program counter register)
#
# @param regex (str) optional regular expression applied to the instruction mnemonic
#
# @return the current instruction represented by a dictionary address->instr_code
#
def disassemble_current_instruction(regex=''):

    # get disassembled output
    output = execute_output('x/i $pc')

    # parse and return output
    return parse_disassembled_output(output, regex)


##
# Disassemble a variable number of instruction starting from the current instruction (pointed by the program counter register)
#
# @param count (int) total number of instructions to disassemble
# @param regex (str) optional regular expression applied to the instruction mnemonic
#
# @return list of instructions represented by a dictionary address->instr_code
# 
def disassemble_current_instructions(count, regex=''):
    
    # get disassembled output
    output = execute_output('x/' + str(count) + 'i $pc')

    # parse and return output
    return parse_disassembled_output(output, regex)

##
# Get process memory mapping
#
# @param regex (str) optional regular expression applied name of the memory area
#
# @return a list of hash maps, where every hash map contains informations about a memory area
#
def process_mappings(regex=''):
    
    mappings = list()

    # get process mappings
    output = execute_output('info proc mappings')

    # parse processes mappings info
    for line in output:
        
        # only right lines
        if re.compile('^\s+0x[0-9a-f]+').search(line):
            field = re.compile('\s+').split(line)

            # provide the last field if not present (memory area name)
            if len(field) < 6:
                field.append('')

            # exclude memory areas that don't match the regexp
            if regex != '':
                if not re.search(regex, field[5]):
                    continue

            # add mapping info to the list
            mappings.append({
                'start': int(field[1], 16),
                'end': int(field[2], 16),
                'size': int(field[3], 16),
                'offset': int(field[4], 16),
                'objfile': field[5]
                })

    return mappings

##
# Assemble x86/x64 assembly instructions and return a buffer containing the assembled machine code
#
# @param instructions (str) assembly instructions separated by a newline (basically an assembly listing)
#
# @return a buffer containing the assembled machine code
#

def assemble_instructions(instructions):

    # temporary files used to compile the instructions
    asmfilename = os.getenv('HOME') + os.sep + 'gdb_assembly_' + str(os.getpid()) + '.S' # assembly code
    objfilename = os.getenv('HOME') + os.sep + 'gdb_assembly_' + str(os.getpid()) + '.o' # compiled code

    # write assembly code (we add marks to extract the compiled fragment from the object file)
    asmfile = open(asmfilename, 'w')
    asmfile.write(
            "\n.ascii \"S___HERE\"\n" +
            instructions   +
            "\n.ascii \"E___HERE\"\n"
            )
    asmfile.close()

    # compile
    execute_external('gcc -c ' + asmfilename + ' -o ' + objfilename)

    # read compiled code
    objfile = open(objfilename, mode='rb')
    buff = objfile.read()
    objfile.close()

    # isolate code fragment
    start = buff.find('S___HERE') + len('S___HERE')
    end   = buff.find('E___HERE')

    # delete files
    os.remove(asmfilename)
    os.remove(objfilename)

    return buff[start:end]

##
# Get the normalized system arguments to fix a little (IMHO) gdb bug:
# when the program is executed with no arguments sys.argv is equal to [''],
# in this case the function returns [], otherwise returns sys.argv immutated
#
# @return the normalized system arguments
#
def normalized_argv ():
    if len(sys.argv) == 1 and sys.argv[0] == '':
        return []
    else:
        return sys.argv

