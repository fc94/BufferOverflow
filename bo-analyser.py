#!/usr/bin/python3

import sys # argv, maxsize
import json
import os # path
import os.path
import ntpath # to get filename from path

try:
	sys.argv[1]
except (NameError, IndexError) as e:
	print ("Must provide a filename.")
	exit()

inputFile = sys.argv[1]
PATH='./'+inputFile

# Verify if the JSON file exists
if not (os.path.isfile(PATH) and os.access(PATH, os.R_OK)):
	print ("Either the file is missing or not readable.")
	exit()

# Open and load JSON file
data = {}
with open(inputFile) as f:
	data = json.load(f)

existent_registers = { "RAX","RBX","RCX","RDX","RDI","RSI","R8","R9","R10",
	"R11","R12","R13","R14","R15","RBP","RSP","RIP" }

# Dictionary of registers like {'RBP': 0}
registers = {}

# Array of objects like: {'name' : 'saved_rbp', 'size' : 8}
stack = []

# Calculates stack size in bytes
def getStackSize():
	return sum(r['size'] for r in stack)

#Print to json file the varoverflow output
def appendVuln_VAR(funcName, overflow_var, overflown_var, address, function):
	output.append({'vulnerability' : 'VAROVERFLOW',
		'fnname' : function,
		'vuln_function' : funcName,
		'overflown_var' : overflown_var,
		'overflow_var' : overflow_var,
		'address' : address})

#Print the Overflow associated to rbp ret and scorruption
def appendVuln_RBP_RET_SCO(funcName, overflow_var, data_read, var_address, address, rbp, function):
	if data_read == None or (var_address - data_read < rbp):
		output.append({"vulnerability" : "RBPOVERFLOW",
			"fnname" : function,
			"overflow_var" : overflow_var,
			"vuln_function" : funcName,
			"address" : address})
	if data_read == None or (var_address - data_read < rbp - 8):
		output.append({"vulnerability" : "RETOVERFLOW",
			"fnname" : function,
			"overflow_var" : overflow_var,
			"vuln_function" : funcName,
			"address" : address})
	if data_read == None or (var_address - data_read < rbp - 16):
		output.append({"vulnerability" : "SCORRUPTION",
			"fnname" : function,
			"overflow_var" : overflow_var,
			"vuln_function" : funcName,
			"overflown_address": "rbp+0x10",
			"address" : address})

# Print the output associated tho invalid access overflow
def appendVuln_ACCS(funcName,overflow_var,overflown_address,address,function):
	output.append({"vulnerability" : "INVALIDACCS",
		"fnname" : function,
		"overflow_var" : overflow_var,
		"overflown_address" : overflown_address,
		"vuln_function" : funcName,
		"address" : address})

# Return the registers used for passing arguments to the function
def argumentsUsed(registers):
	Registers_used_for_arguments = {"RCX","RDX","RDI","RSI","R8","R9"}
	Registers_arguments = {}
	for r in registers:
		if r in Registers_used_for_arguments:
			Registers_arguments[r] =  registers[r]

	return Registers_arguments

# Check if all arguments are buffer type
def areAllArgumentsBufferType(registers_arguments,variables):
	for r in registers_arguments:
		for v in variables:
			if v["addr"] == registers_arguments[r] and v["type"] != "buffer":
				return False
	return True

filename = ntpath.basename(inputFile)
filename, file_extension = os.path.splitext(filename)

# objects to write to output file
output = []

#####################################################################
# Instruction to consider:                                          #
#    Basic: ret, leave, nop, push, pop,                             #
#           call (of dangerous functions), mov, lea, sub, add       #
#    Advanced: call (of generic functions), cmp, test, je, jmp, jne #
#####################################################################
def parseFunc(funcName, parameters):

	global filename
	global file_extension
	global output
	global registers
	global existent_registers
	global stack

	try:
		n_instructions = data[funcName]['Ninstructions'] # Number of instructions
		variables = data[funcName]['variables'] # List of variables
		if n_instructions != len(data[funcName]['instructions']):
			print ("Ninstructions doesn't match length of instructions array.")
			exit()
	except KeyError:
		print ("Invalid file.")
		exit()

	# Convert address of variables to decimal, "initialize" content, and insert unallocated space
	for v in variables:
		v['addr'] = int(v['address'].split('0x')[1], 16)
		v['content_size'] = None

	# Sort variables by address
	variables = sorted(variables, key=lambda kv: kv['addr'])

	temp = {}

	cmpResult = False

	for i in range(0,len(variables),2):
		try:
			pos1 = variables[i+1]['addr']
			pos0 = variables[i]['addr']
			bytes1 = variables[i+1]['bytes']
			bytes0 = variables[i]['bytes']
		except:
			break
		# If address of variable above minus the address of current variable is
		# bigger than the size of the variable above, then there is padding
		# between these variables
		if pos1 - pos0 > bytes1:
			bytes3 = pos1 - pos0 - bytes1
			variables.append({
						'bytes' : bytes3,
						'type' : 'unallocated',
						'name' : 'unallocated',
						'address' : 'rbp-' + str(hex(pos0 + bytes3)),
						'addr' : pos0 + bytes3,
						'content_size' : None
					})
	variables = sorted(variables, key=lambda kv: kv['addr'])

	# Sort instructions by position in case they aren't.
	instructions = sorted(data[funcName]['instructions'], key=lambda kv: kv['pos'])

	k = -1
	while k+1 < len(instructions):
		k += 1
		i = instructions[k]

		if i['op'] == "ret":
			# End of function
			# Finish writing output and exit
			with open(filename + ".output.json", 'w') as outfile:
				json.dump(output, outfile, indent = 4, sort_keys = True)

		elif i['op'] == "leave":
			# End of function, before ret
			pass
		elif i['op'] == "nop":
			# Nothing to do
			pass
		elif i['op'] == "push":
			# TODO More case scenarios

			# Begin the function
			if i['args']['value'] == "rbp":
				stack.append({'name' : 'saved_rbp', 'size' : 8})
		elif i['op'] == "pop":
			# TODO Can be improved (eg. what if size is not multiple of 8?)
			if stack[-1]['size'] > 8:
				stack[-1]['size'] -=8
			else:
				stack.pop()
		elif i['op'] == "mov":
			# Moving values to variables can be ignored...
			if 'BYTE PTR' in i['args']['dest']:
				address = i['args']['dest'][10:-1]
				overflown_address = address
				if "rbp" in address:
					if address[3] == '-':
						address = address[4:]
						value = int(address, 16)
						value = registers['RBP']+value
					else:
						address = address[4:]
						value = int(address, 16)
						value = registers['RBP']-value
					for v in variables:
						# If there's direct access to padding between variables
						if v["type"] == "unallocated":
							if v["addr"] > value and value > (v["addr"] - v["bytes"]):
								output.append({"overflown_address": overflown_address,
									"op" : "mov",
									"vuln_function" : funcName,
									"address" : i['address'],
									"vulnerability" : "INVALIDACCS"})
						# Content size of buffer may change if '\0' is added
						elif v["type"] == "buffer" and i['args']['value'] == "0x0":
							if(v["addr"] > value and value > (v["addr"]-v["bytes"])):
								length = v["addr"]-value # From start of buffer to '\0'
								if v["content_size"] == None or v["content_size"] > length:
									v["content_size"]=length
					if value < registers['RBP'] and value > registers['RBP'] - 8:
						output.append({"overflown_address": overflown_address,
							"op" : "mov",
							"vuln_function" : funcName,
							"address" : i['address'],
							"vulnerability" : "RBPOVERFLOW"})
					elif value < registers['RBP'] - 8 and value > registers['RBP'] - 16:
						output.append({"overflown_address": overflown_address,
							"op" : "mov",
							"vuln_function" : funcName,
							"address" : i['address'],
							"vulnerability" : "RETOVERFLOW"})

			# Move to a register of 8 bytes (considers half registers)
			if any (i['args']['dest'][1:].upper() in s for s in existent_registers):
				register = 'R' + i['args']['dest'][1:].upper()

				# Move RSP to RBP (or other register)
				if i['args']['value'] == "rsp":
					registers[register] = getStackSize() - 8
					if i['args']['dest'] == "rbp":
						for v in variables:
							v['addr'] += registers['RBP']
						variables += parameters

				# Move one register to another
				elif i['args']['value'].upper() in registers:
					value = registers[i['args']['value'].upper()]
					registers[register] = value

				# Move value to register
				elif i['args']['value'][:2] == "0x":
					hexa = i['args']['value'][2:]
					value = int(hexa, 16)
					registers[register] = value

				# Moving from some place in the stack to register
				elif 'PTR' in i['args']['value'] and i['args']['value'] in temp:
					registers[register] = temp[i['args']['value']]

			# Moving to some place in the stack
			if 'PTR' in i['args']['dest']:
				# Move one register to "stack"
				if i['args']['value'].upper() in registers:
					value = registers[i['args']['value'].upper()]
					temp[i['args']['dest']] = value
				# Move value to "stack"
				if i['args']['value'][:2] == "0x":
					hexa = i['args']['value'][2:]
					value = int(hexa, 16)
					temp[i['args']['dest']] = value

		elif i['op'] == "lea":

			if i['args']['dest'].upper() in existent_registers:
				register = i['args']['dest'].upper()
				if "[rbp-" in i['args']['value']:
					hexa = i['args']['value'].split('0x')[1][0:-1]
					value = int(hexa, 16) + registers['RBP']
					registers[register] = value

		elif i['op'] == "sub":

			# Allocate memory for local variables
			if i['args']['dest'] == "rsp":
				if i['args']['value'].startswith("0x"):
					hexa = i['args']['value'][2:]
					value = int(hexa, 16)
					stack.append({'name': 'localvars', 'size' : value})

			# Subtract value to register
			elif any (i['args']['dest'][1:].upper() in s for s in existent_registers):
				register = 'R' + i['args']['dest'][1:].upper()
				if i['args']['value'][:2] == "0x":
					hexa = i['args']['value'][2:]
					value = int(hexa, 16)
					if register in registers:
						registers[register] -= value

		elif i['op'] == "add":

			# Allocate memory for local variables
			if i['args']['dest'] == "rsp":
				if i['args']['value'].startswith("0x"):
					hexa = i['args']['value'][2:]
					value = int(hexa, 16)
					# https://stackoverflow.com/questions/24563786/conversion-from-hex-to-signed-dec-in-python/32276534
					value = -(-(value & 0x80000000) | (value & 0x7fffffff))
					stack.append({'name': 'localvars', 'size' : value})

			# Add value to register
			if any (i['args']['dest'][1:].upper() in s for s in existent_registers):
				register = 'R' + i['args']['dest'][1:].upper()
				if i['args']['value'][:2] == "0x":
					hexa = i['args']['value'][2:]
					value = int(hexa, 16)
					if register in registers:
						registers[register] += value

		elif i['op'] == "cmp":
			arg0 = None
			arg1 = None
			if 'PTR' in i['args']['arg0'] and i['args']['arg0'] in temp:
				arg0 = temp[i['args']['arg0']]
			elif i['args']['arg0'].startswith("0x"):
				arg0 = int(i['args']['arg0'][2:], 16)
			elif i['args']['arg0'].upper() in registers:
				arg0 = registers[i['args']['arg0'].upper()]

			if 'PTR' in i['args']['arg1'] and i['args']['arg1'] in temp:
				arg1 = temp[i['args']['arg1']]
			elif i['args']['arg1'].startswith("0x"):
				arg1 = int(i['args']['arg1'][2:], 16)
			elif i['args']['arg1'].upper() in registers:
				arg1 = registers[i['args']['arg1'].upper()]

			if arg0 == arg1:
				cmpResult = True

		elif i['op'] == "jne":
			if not cmpResult:
				j = -1
				while j+1 < len(instructions):
					j += 1
					if instructions[j]["address"] == i['args']['address']:
						k = j-1
						break
				if k == j-1:
					continue

		elif i['op'] == "je":
			if cmpResult:
				j = -1
				while j+1 < len(instructions):
					j += 1
					if instructions[j]["address"] == i['args']['address']:
						k = j-1
						break
				if k == j-1:
					continue

		elif i['op'] == "jmp":
			j = -1
			while j+1 < len(instructions):
				j += 1
				if instructions[j]["address"] == i['args']['address']:
					k = j-1
					break
			if k == j-1:
				continue

		############################################################
		# Dangerous functions to consider                          #
		#    Basic: gets, strcpy, strcat, fgets, strncpy, strncat  #
		#    Advanced: sprintf, scanf, fscanf, snprintf, read      #
		#                                                          #
		# The arguments of functions are passed in the following   #
		# order in the registers:                                  #
		#                                                          #
		# RDI,RSI,RDX,RCX,R8,R9 + stack for arguments beyond the   #
		# 6th (with 7th argument being the one on top)             #
		#                                                          #
		# respectively for the 1st, 2nd, 3rd, 4th, 5th, and 6th    #
		# argument of a function.                                  #
		############################################################
		elif i['op']=="call":

			# Generic functions
			if "@plt" not in i["args"]["fnname"]:
				# TODO Doesn't check stack arguments and non-address values
				parameters = []
				if 'RDI' in registers:
					for v in variables:
						if registers['RDI'] == v['addr']:
							parameters.append(v)
					if 'RSI' in registers:
						for v in variables:
							if registers['RSI'] == v['addr']:
								parameters.append(v)
						if 'RDX' in registers:
							for v in variables:
								if registers['RDX'] == v['addr']:
									parameters.append(v)
							if 'RCX' in registers:
								for v in variables:
									if registers['RCX'] == v['addr']:
										parameters.append(v)
								if 'R8' in registers:
									for v in variables:
										if registers['R8'] == v['addr']:
											parameters.append(v)
									if 'R9' in registers:
										for v in variables:
											if registers['R9'] == v['addr']:
												parameters.append(v)
				parseFunc(i["args"]["fnname"][1:-1], parameters)

			# Reads characters from the standard input (stdin) and stores them as
			# a C string into str until a newline character or the end-of-file is
			# reached. The newline character, if found, is not copied into str.
			# A terminating null character is automatically appended after the
			# characters copied to str.
			elif "<gets@plt>" == i["args"]["fnname"]:

				# Variable responsible for the overflow (usually a buffer)
				overflow_var = None

				buf = registers['RDI']

				for v in variables:
					if buf == v['addr']:
						overflow_var = v['name']
						break

				for v in variables:
					# If RDI value (address of buffer) is higher
					# or within the variable address, then it is overflown
					if v['addr'] > registers['RBP'] and (buf > v['addr']):
						if v['type'] != 'unallocated':
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'], "gets")

						else:
							appendVuln_ACCS(funcName, overflow_var, v['address'], i["address"], "gets")

				appendVuln_RBP_RET_SCO(funcName, overflow_var, None, buf, i["address"], registers['RBP'], "gets")


			# Reads characters from stream and stores them as a C string into
			# str until (num-1) characters have been read or either a newline or
			# the end-of-file is reached, whichever happens first.
			# A newline character makes fgets stop reading, but it is considered
			# a valid character by the function and included in the string copied to str.
			# A terminating null character is automatically appended after the
			# characters copied to str.
			elif "<fgets@plt>" == i["args"]["fnname"]:

				# Variable responsible for the overflow (usually a buffer)
				overflow_var = None

				buf = registers['RDI']
				length = registers['RSI']

				for v in variables:
					if buf == v['addr']:
						v['content_size'] = length
						if length <= v['bytes']:
							length = 0
						else:
							overflow_var = v['name']
						break

				if length == 0:
					continue

				for v in variables:
					# If RDI value (address of buffer) is higher than variable address
					# and the content length overflows the variable
					if v['addr'] > registers['RBP'] and buf-length < v['addr'] and buf > v['addr']:
						if v['type'] != 'unallocated':
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'], "fgets")

						else:
							appendVuln_ACCS(funcName, overflow_var, v['address'], i['address'], "fgets")

				appendVuln_RBP_RET_SCO(funcName, overflow_var, length, buf, i["address"], registers['RBP'], "fgets")
			

			# Copies the C string pointed by source into the array pointed
			# by destination, including the terminating null character (and
			# stopping at that point).
			elif "<strcpy@plt>" == i["args"]["fnname"]:

				# Variable responsible for the overflow (usually a buffer)
				overflow_var = None

				buf1 = registers['RDI']
				buf2 = registers['RSI']

				# Find size of buffer 2
				for v in variables:
					if buf2 == v['addr']:
						if v['content_size'] != None:
							buf2_size = v['content_size']
						else:
							# FIXME Can be bigger or stop at '\0' if there's any
							buf2_size = sys.maxsize

				for v in variables:
					if buf1 == v['addr']:
						# Set content size of buffer 1
						v['content_size'] = buf2_size
						if buf2_size <= v['bytes']:
							buf2_size = 0
						else:
							overflow_var = v['name']
						break

				if buf2_size == 0:
					continue

				for v in variables:
					# If RDI value (address of buffer) is higher than variable address
					# and the content length overflows the variable
					if v['addr'] > registers['RBP'] and buf1-buf2_size < v['addr'] and buf1 > v['addr']:
						if v['type'] != 'unallocated':
							appendVuln_VAR(funcName, overflow_var, v['name'], i["address"], "strcpy")
						else:
							appendVuln_ACCS(funcName, overflow_var, v['address'], i["address"], "strcpy")

				appendVuln_RBP_RET_SCO(funcName, overflow_var, buf2_size, buf1, i["address"], registers['RBP'], "strcpy")
				

			# Copies the first num characters of source to destination. If the end
			# of the source C string (which is signaled by a null-character) is found
			# before num characters have been copied, destination is padded with zeros
			# until a total of num characters have been written to it.
			# No null-character is implicitly appended at the end of destination if
			# source is longer than num. Thus, in this case, destination shall not be
			# considered a null terminated C string (reading it as such would overflow).
			elif "<strncpy@plt>" == i["args"]["fnname"]:

				# Variable responsible for the overflow (usually a buffer)
				overflow_var = None

				buf1 = registers['RDI']
				buf2 = registers['RSI']
				length = registers['RDX']

				# Find size of buffer 2
				for v in variables:
					if buf2 == v['addr']:
						if v['content_size'] != None:
							buf2_size = v['content_size']
						else:
							# FIXME Can be bigger or stop at '\0' if there's any
							buf2_size = sys.maxsize

				# Set content size of buffer 1
				for v in variables:
					if buf1 == v['addr']:
						v['content_size'] = buf2_size
						# If '\0' is not appended to buffer...
						if length < buf2_size:
							# FIXME Can be bigger or stop at '\0' if there's any
							v['content_size'] = sys.maxsize

				for v in variables:
					if buf1 == v['addr']:
						if length <= v['bytes']:
							length = 0
						else:
							overflow_var = v['name']
						break

				if length == 0:
					continue

				for v in variables:
					# If RDI value (address of buffer) is higher than variable address
					# and the content length overflows the variable
					if v['addr'] > registers['RBP'] and buf1-length < v['addr'] and buf1 > v['addr']:
						if v['type'] != 'unallocated':
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'], "strncpy")

						else:
							appendVuln_ACCS(funcName, overflow_var, v['address'], i["address"], "strncpy")

				appendVuln_RBP_RET_SCO(funcName, overflow_var, length, buf1, i["address"], registers['RBP'], "strncpy")


			# Appends a copy of the source string to the destination string.
			# The terminating null character in destination is overwritten by
			# the first character of source, and a null-character is included
			# at the end of the new string formed by the concatenation of both
			# in destination.
			elif "<strcat@plt>" == i["args"]["fnname"]:

				# Variable responsible for the overflow (usually a buffer)
				overflow_var = None

				buf1 = registers['RDI']
				buf2 = registers['RSI']

				# Find size of buffers
				for v in variables:
					if buf1 == v['addr']:
						if v['content_size'] != None:
							buf1_size = v['content_size']
						else:
							# FIXME Can be bigger or stop at '\0' if there's any
							buf1_size = sys.maxsize
					elif buf2 == v['addr']:
						if v['content_size'] != None:
							buf2_size = v['content_size']
						else:
							# FIXME Can be bigger or stop at '\0' if there's any
							buf2_size = sys.maxsize

				# -1 because nullbyte of 1st string is overwritten
				length = buf1_size + buf2_size - 1

				for v in variables:
					if buf1 == v['addr']:
						v['content_size'] = length
						if length <= v['bytes']:
							length = 0
						else:
							overflow_var = v['name']
						break

				if length == 0:
					continue

				for v in variables:
					# If RDI value (address of buffer) is higher than variable address
					# and the content length overflows the variable
					if v['addr'] > registers['RBP'] and buf1-length < v['addr'] and buf1 > v['addr']:
						if v['type'] != 'unallocated':
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'], "strcat")

						else:
							appendVuln_ACCS(funcName, overflow_var, v['address'], i["address"], "strcat")
				appendVuln_RBP_RET_SCO(funcName, overflow_var, length, buf1, i["address"], registers['RBP'], "strcat")

			# strncat: Appends the first num characters of source to destination,
			# plus a terminating null-character.
			# If the length of the C string in source is less than num,
			# only the content up to the terminating null-character is copied.
			elif "<strncat@plt>" == i["args"]["fnname"]:

				# Variable responsible for the overflow (usually a buffer)
				overflow_var = None

				buf1 = registers['RDI']
				buf2 = registers['RSI']
				num = registers['RDX'] + 1 # Because of '\0'

				# Find size of buffers
				for v in variables:
					if buf1 == v['addr']:
						if v['content_size'] != None:
							buf1_size = v['content_size']
						else:
							# FIXME Can be bigger or stop at '\0' if there's any
							buf1_size = sys.maxsize
					elif buf2 == v['addr']:
						if v['content_size'] != None:
							buf2_size = v['content_size']
						else:
							# FIXME Can be bigger or stop at '\0' if there's any
							buf2_size = sys.maxsize

				if buf2_size < num:
					num = buf2_size

				# -1 because nullbyte of 1st string is overwritten
				length = buf1_size + num - 1

				for v in variables:
					if buf1 == v['addr']:
						v['content_size'] = length
						if length <= v['bytes']:
							length = 0
						else:
							overflow_var = v['name']
						break

				if length == 0:
					continue

				for v in variables:
					# If RDI value (address of buffer) is higher than variable address
					# and the content length overflows the variable
					if v['addr'] > registers['RBP'] and buf1-length < v['addr'] and buf1 > v['addr']:
						if v['type'] != 'unallocated':
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'], "strncat")
						else:
							appendVuln_ACCS(funcName, overflow_var, v['address'], i["address"], "strncat")
				appendVuln_RBP_RET_SCO(funcName, overflow_var, length, buf1, i["address"], registers['RBP'], "strncat")

			# FIXME Can take infinite arguments...
			elif "<__isoc99_scanf@plt>" in i["args"]["fnname"]:

				# Variable responsible for the overflow (usually a buffer)
				overflow_var = None
				Reggisters_with_arguments = {}
				Reggisters_with_arguments = argumentsUsed(registers)

				# FIXME Verify RDI to see what type of variable we're reading

				# FIXME May not receive extra arguments
				buf = registers['RSI']

				for v in variables:
					if buf == v['addr']:
						v['content_size'] = sys.maxsize # FIXME Can be bigger or stop at '\0' if there's any
						overflow_var = v['name']
						break

				for v in variables:
					# If address of buffer is higher than variable address
					# FIXME Overflow depends on type of variable we're reading
					if v['addr'] > registers['RBP'] and buf > v['addr']:
						if v['type'] != 'unallocated':
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'], "scanf")

						else:
							appendVuln_ACCS(funcName, overflow_var, v['address'], i["address"], "scanf")

				# FIXME Overflow depends on type of variable we're reading
				output.append({"vulnerability" : "RBPOVERFLOW",
					"fnname" : "__isoc99_scanf",
					"overflow_var" : overflow_var,
					"vuln_function" : funcName,
					"address" : i["address"]})

				output.append({"vulnerability" : "RETOVERFLOW",
					"fnname" : "__isoc99_scanf",
					"overflow_var" : overflow_var,
					"vuln_function" : funcName,
					"address" : i["address"]})

				output.append({"vulnerability" : "SCORRUPTION",
					"fnname" : "__isoc99_scanf",
					"overflow_var" : overflow_var,
					"vuln_function" : funcName,
					"overflown_address": "rbp+0x10",
					"address" : i["address"]})

			# FIXME Can take infinite arguments...
			elif "<__isoc99_fscanf@plt>" in i["args"]["fnname"]:

				# Variable responsible for the overflow (usually a buffer)
				overflow_var = None
				Reggisters_with_arguments = {}
				Reggisters_with_arguments = argumentsUsed(registers)
				# XXX RDI is ignored

				# FIXME Verify RSI to see what type of variable we're reading

				# FIXME May not receive extra arguments
				buf = registers['RDX']

				for v in variables:
					if buf == v['addr']:
						v['content_size'] = sys.maxsize # FIXME Can be bigger or stop at '\0' if there's any
						overflow_var = v['name']
						break

				for v in variables:
					# If address of buffer is higher than variable address
					# FIXME Overflow depends on type of variable we're reading
					if v['addr'] > registers['RBP'] and buf > v['addr']:
						if v['type'] != 'unallocated':
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'], "__isoc99_fscanf")
						else:
							appendVuln_ACCS(funcName, overflow_var, v['address'], i["address"], "__isoc99_fscanf")


				# FIXME Overflow depends on type of variable we're reading
				output.append({"vulnerability" : "RBPOVERFLOW",
					"fnname" : "__isoc99_fscanf",
					"overflow_var" : overflow_var,
					"vuln_function" : funcName,
					"address" : i["address"]})

				output.append({"vulnerability" : "RETOVERFLOW",
					"fnname" : "__isoc99_fscanf",
					"overflow_var" : overflow_var,
					"vuln_function" : funcName,
					"address" : i["address"]})

				output.append({"vulnerability" : "SCORRUPTION",
					"fnname" : "__isoc99_fscanf",
					"overflow_var" : overflow_var,
					"vuln_function" : funcName,
					"overflown_address": "rbp+0x10",
					"address" : i["address"]})


			#Read: The read() function shall attempt to read nbyte bytes
			#from the file associated with the open file descriptor
			#fildes into the buffer pointed to by buf
			elif "<read@plt>" in i["args"]["fnname"]:
				Reggisters_with_arguments = {}
				Reggisters_with_arguments = argumentsUsed(registers)
				for v in variables:
					var_addr = 0
					buf2_size = 0
					#if the highest address corresponds to the function argument it stores the value
					if(v["addr"]==registers["RSI"]):
						var_addr = v["addr"]
						overflow_var= v["name"]
						data_read = registers["RDX"]
						v['content_size']=data_read

				for v in variables:
					if(var_addr-data_read<v["addr"]<var_addr):
						if(v["type"]!="unallocated"):
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'],"read")
						else:
							appendVuln_ACCS(funcName, overflow_var, v['address'], i['address'], "read")
				appendVuln_RBP_RET_SCO(funcName, overflow_var, data_read, var_addr, i["address"], registers['RBP'], "read")

			#Snprintf: formats and stores a series of characters and values in the array buffer
			#The snprintf() function with the addition of the n argument,
			#which indicates the maximum number of characters (including at the end of null character)
			#to be written to buffer
			elif "<snprintf@plt>" in i["args"]["fnname"]:
				Reggisters_with_arguments = {}
				Reggisters_with_arguments = argumentsUsed(registers)
				data_read = registers["RSI"]
				var_addr = 0
				for v in variables:
					if(v['addr']==registers['RDI']):
						overflow_var = v["name"]
						var_addr = v["addr"]
						v['content_size']=data_read

				for v in variables:
					if(var_addr-data_read<v["addr"]<var_addr):
						if(v["type"]=="unallocated"):
							appendVuln_ACCS(funcName, overflow_var, v['address'], i["address"], "snprintf")
						else:
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'], "snprintf")
				appendVuln_RBP_RET_SCO(funcName, overflow_var, data_read, var_addr, i["address"], registers['RBP'], "snprintf")

			# Sprintf: Instead of printing on console,
			#it store output on char buffer which are specified in sprintf
			elif "<sprintf@plt>" in i["args"]["fnname"]:
				Registers = argumentsUsed(registers)
				data_read = 0
				
				# cycle to find how much bytes will be written to the dest buffer case exists more than one source buffer
				for r in Registers:
					if(r!='RSI' and r!='RDI'):
						for v in variables:
							if(Registers[r]==v['addr']):
								if(v['content_size']==None):
									data_read = None
									break
								else:
									data_read = data_read + v['content_size']
				for v in variables:
					if(v['addr']==registers['RDI']):
						overflow_var = v["name"]
						var_addr = v["addr"]
						v['content_size']= data_read

				
				for v in variables:
					if(data_read==None or var_addr-data_read<v["addr"]<var_addr):
						if(v["type"]=="unallocated"):
							appendVuln_ACCS(funcName, overflow_var, v['address'], i["address"], "sprintf")
						else:
							appendVuln_VAR(funcName, overflow_var, v['name'], i['address'], "sprintf")
				appendVuln_RBP_RET_SCO(funcName, overflow_var, data_read, var_addr, i["address"], registers['RBP'], "sprintf")

			#print("Stack: " + str(stack))
			#print("Registers: " + str(registers))
			#print("Variables: " + str(variables))
			#print("Parameters: " + str(parameters))
			#print("\n")

		else:
			print("Assembly function not recognized: " + i['op'])
			exit()

parseFunc('main', [])