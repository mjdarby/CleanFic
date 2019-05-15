from enum import Enum
import curses
import sys

# Enums
Form = Enum('Form', 'Short Long Variable')
Operand = Enum('Operand', 'ZeroOP OneOP TwoOP VAR')
OperandType = Enum('OperandType', 'Large Small Variable')
Alphabet = Enum('Alphabet', 'A0 A1 A2')

# Statics
NeedBranchOffset = ["jin","jg","jl","je","inc_chk","dec_chk","jz","get_child","get_sibling","save1","restore1","test_attr","test","verify", "scan_table", "piracy", "check_arg_count"]
NeedStoreVariable = ["call","and","get_parent","get_child","get_sibling","get_prop","add","sub","mul","div","mod","loadw","loadb", "get_prop_addr", "get_prop_len", "get_next_prop", "random", "load", "and", "or", "not", "call_2s", "call_vs2", "call_1s", "call_vs", "read_char", "scan_table", "save4", "restore4", "art_shift", "log_shift", "set_font", "read5", "save_undo", "catch"]
NeedTextLiteral = ["print","print_ret"]

def needsStoreVariable(opcode):
  return opcode in NeedStoreVariable

def needsBranchOffset(opcode):
  return opcode in NeedBranchOffset

def needsTextLiteral(opcode):
  return opcode in NeedTextLiteral

def getOperandCount(form, opcode_byte):
  if (form == Form.Long):
    opcount = Operand.TwoOP
  elif (form == Form.Short):
    if (opcode_byte & 0b0110000 == 0b0110000):
      opcount = Operand.ZeroOP
    else:
      opcount = Operand.OneOP
  else: # (form == Form.Variable)
    if (opcode_byte & 0b0100000 == 0b0100000):
      opcount = Operand.VAR
    else:
      opcount = Operand.TwoOP
  return opcount

def getOperandTypeFromBytes(byte):
  if (byte == 0):
    return OperandType.Large
  elif (byte == 1):
    return OperandType.Small
  else: # (byte == 2)
    return OperandType.Variable

def getOperandType(form, opcode_bytes):
  if (form == Form.Short):
    if (opcode_bytes & 0b00100000 == 0b00100000):
      return [OperandType.Variable]
    elif (opcode_bytes & 0b00010000 == 0b00010000):
      return [OperandType.Small]
    elif (opcode_bytes & 0b00000000 == 0b00000000):
      return [OperandType.Large]
  elif (form == Form.Long):
    operand_types = []
    if (opcode_bytes & 0b01000000 == 0b01000000):
      operand_types.append(OperandType.Variable)
    else:
      operand_types.append(OperandType.Small)
    if (opcode_bytes & 0b00100000 == 0b00100000):
      operand_types.append(OperandType.Variable)
    else:
      operand_types.append(OperandType.Small)
    return operand_types
  else: # form == Variable
    operand_types = []
    if (opcode_bytes & 0b11000000 == 0b11000000):
      return operand_types
    else:
      operand_types.append(getOperandTypeFromBytes(opcode_bytes >> 6))
    if (opcode_bytes & 0b00110000 == 0b00110000):
      return operand_types
    else:
      operand_types.append(getOperandTypeFromBytes((opcode_bytes & 0b00110000) >> 4))
    if (opcode_bytes & 0b00001100 == 0b00001100):
      return operand_types
    else:
      operand_types.append(getOperandTypeFromBytes((opcode_bytes & 0b00001100) >> 2))
    if (opcode_bytes & 0b00000011 == 0b00000011):
      return operand_types
    else:
      operand_types.append(getOperandTypeFromBytes(opcode_bytes & 0b00000011))
    return operand_types


class Game:
  def __init__(self, memory, display):
    self.memory = memory
    self.display = display
    self.version = self.memory.getVersion()

  def loop(self):
    while True:
      instr = self.getInstruction(self.memory.pc)
      instr.run()

  def getInstruction(self, addr):
    next_byte = addr
    # First, determine the opcode
    first_opcode_byte = self.memory.getByte(addr)
    next_byte += 1
    opcode = None
    form = None
    opcount = None
    operands = []
    store_variable = None
    branch_offset = None
    text_to_print = None
    func = None
    operand_types = []

    # Figure out instruction form
    if ((first_opcode_byte & 0b11000000) == 0b11000000):
      form = Form.Variable
    elif ((first_opcode_byte & 0b10000000) == 0b10000000):
      form = Form.Short
    else:
      form = Form.Long

    # Figure out the operand count and type(s)
    opcount = getOperandCount(form, first_opcode_byte)
    if (not opcode):
      opcode, func = Instruction.getOpcode(first_opcode_byte, opcount, form)

    if (opcount != Operand.ZeroOP):
      if (form == Form.Variable):
        operand_types = getOperandType(form, self.memory.getByte(next_byte))
        next_byte += 1
        # Special case: call_vs2 and call_vn2 can have 4 more args
        if (opcode == 'call_vs2' or opcode == 'call_vn2'):
          operand_types += getOperandType(form, self.memory.getByte(next_byte))
          next_byte += 1
      else:
        operand_types = getOperandType(form, first_opcode_byte)

      # Now get that many operands...
      for operand_type in operand_types:
        if (operand_type == OperandType.Large):
          operands.append(self.memory.getWord(next_byte))
          next_byte += 2
        if (operand_type == OperandType.Small):
          operands.append(self.memory.getByte(next_byte))
          next_byte += 1
        if (operand_type == OperandType.Variable):
          operands.append(self.memory.getByte(next_byte))
          next_byte += 1

    # If this opcode needs a store variable, get it...
    if (needsStoreVariable(opcode)):
      store_variable = self.memory.getByte(next_byte)
      next_byte += 1

    # If this opcode needs a branch offset, get that...
    branch_on_true = None
    if (needsBranchOffset(opcode)):
      branch_byte = self.memory.getByte(next_byte)
      branch_on_true = (branch_byte & 0b10000000) == 0b10000000
      next_byte += 1
      if ((branch_byte & 0b01000000) == 0b01000000):
        branch_offset = branch_byte & 0b00111111
      else:
        branch_byte_two = self.memory.getByte(next_byte)
        # Annoying 15-bit sign conversion
        val = ((branch_byte & 0b00011111) << 8) + branch_byte_two
        if ((branch_byte & 0b00100000) == 0b00100000):
          val = -(0x2000 - val)
        branch_offset = val
        next_byte += 1

    # If this opcode needs a string literal, get that...
    text_literal = None
    if (needsTextLiteral(opcode)):
      text_literal, next_byte = self.memory.getEncodedTextLiteral(next_byte)

    instr_length = next_byte - addr

    return Instruction(self,
                       func,
                       operands,
                       operand_types,
                       store_variable,
                       branch_on_true,
                       branch_offset,
                       text_to_print,
                       text_literal,
                       instr_length)

  def callRoutine(self, routine, pc):
    self.memory.routine_callstack.append(routine)
    self.memory.pc = pc

class Display:
  def __init__(self):
    self.stdscr = None

class RoutineCall:
  def __init__(self):
    self.local_variables = []
    self.stack = []
    self.return_address = 0x0000

class Memory:
  def __init__(self,
               raw_memory):
    self.raw = raw_memory
    self.mem = bytearray(raw_memory)
    self.pc = self.getWord(0x06)
    self.routine_callstack = []

  def getByte(self, addr):
    return self.mem[addr]

  def getWord(self, addr):
    return (self.getByte(addr) << 8) + self.getByte(addr+1)

  def getVersion(self):
    # First byte of file is Z-Machine version
    return self.getByte(0x0)

  def getVariable(self, variable_number):
    if (variable_number == 0x00):
      return self.popStack()
    if (variable_number > 0x00 and variable_number < 0x10):
      return self.getLocalVariable(variable_number - 0x01)
    else:
      return self.getGlobalVariableValue(variable_number - 0x10)

  def getStack(self):
    if (len(self.routine_callstack) > 0):
      return self.routine_callstack[-1].stack
    return self.stack

  def popStack(self):
    return self.getStack().pop()

  def getLocalVariable(self, variable_number):
    top_routine = self.routine_callstack[-1]
    return top_routine.local_variables[variable_number]

  def getGlobalVariableAddr(self, variable_number):
    return self.global_table_start + (variable_number * 2)

  def getGlobalVariableValue(self, variable_number):
    return self.getWord(self.getGlobalVariableAddr(variable_number))

  def getEncodedTextLiteral(self, next_byte):
    chars = self.getWord(next_byte)
    text_literal = []
    # First two-byte set with the first bit set to '0' is the end of the stream
    while ((chars & 0x8000) != 0x8000):
      text_literal.append(chars)
      next_byte += 2
      chars = self.getWord(next_byte)
    text_literal.append(chars)
    next_byte += 2
    return (text_literal, next_byte)

class Instruction:
  opcodeMap = {}

  def __init__(self,
               game,
               func,
               operands,
               operand_types,
               store_variable,
               branch_on_true,
               branch_offset,
               text_to_print,
               encoded_string_literal,
               instr_length):
    self.operands = operands
    self.operand_types = operand_types
    self.store_variable = store_variable
    self.branch_on_true = branch_on_true
    self.branch_offset = branch_offset
    self.text_to_print = text_to_print
    self.encoded_string_literal = encoded_string_literal
    self.instr_length = instr_length
    bound_func = func.__get__(self, self.__class__)
    self.func = bound_func
    self.game = game

  def run(self):
    self.func()

  def getOpcode(byte, operand_type, form):
    key = byte
    if operand_type == Operand.TwoOP:
      key = byte & 0b00011111
    elif operand_type == Operand.OneOP:
      key = byte & 0b00001111
    elif operand_type == Operand.ZeroOP:
      key = byte & 0b00001111
    return Instruction.opcodeMap[operand_type][key]

  def decodeOperands(self):
    oper_zip = zip(self.operand_types, self.operands)
    decoded_opers  = []
    for operand_pair in oper_zip:
      if (operand_pair[0] == OperandType.Variable):
        decoded_opers.append(self.game.memory.getVariable(operand_pair[1]))
      else:
        decoded_opers.append(operand_pair[1])
    return decoded_opers

  def je(self):
      raise Exception("Unimplemented")
  def jl(self):
      raise Exception("Unimplemented")
  def jg(self):
      raise Exception("Unimplemented")
  def dec_chk(self):
      raise Exception("Unimplemented")
  def inc_chk(self):
      raise Exception("Unimplemented")
  def jin(self):
      raise Exception("Unimplemented")
  def test(self):
      raise Exception("Unimplemented")
  def or_1(self):
      raise Exception("Unimplemented")
  def and_1(self):
      raise Exception("Unimplemented")
  def test_attr(self):
      raise Exception("Unimplemented")
  def set_attr(self):
      raise Exception("Unimplemented")
  def clear_attr(self):
      raise Exception("Unimplemented")
  def store(self):
      raise Exception("Unimplemented")
  def insert_obj(self):
      raise Exception("Unimplemented")
  def loadw(self):
      raise Exception("Unimplemented")
  def loadb(self):
      raise Exception("Unimplemented")
  def get_prop(self):
      raise Exception("Unimplemented")
  def get_prop_addr(self):
      raise Exception("Unimplemented")
  def get_next_prop(self):
      raise Exception("Unimplemented")
  def add(self):
      raise Exception("Unimplemented")
  def sub(self):
      raise Exception("Unimplemented")
  def mul(self):
      raise Exception("Unimplemented")
  def div(self):
      raise Exception("Unimplemented")
  def mod(self):
      raise Exception("Unimplemented")
  def call(self):
    decoded_opers = self.decodeOperands()
    calling_addr = decoded_opers[0]

    # Calling address 0 results in returning 0 instantly
    if (calling_addr == 0):
      self.game.setVariable(self.store_variable, 0)
      self.game.advancePc(self.instr_length)
      return

    # Create a new routine object
    new_routine = RoutineCall()
    # Grab the return addr
    new_routine.return_address = self.game.memory.pc + self.instr_length
    new_routine.store_variable = self.store_variable
    new_routine.is_callback = False

    routine_address = 2 * calling_addr

    # How many local variables?
    local_var_count = self.game.memory.getByte(routine_address)

    # Get the default values
    for i in range(local_var_count):
      variable_value = self.game.memory.getWord(routine_address + 1 + (2*i))
      new_routine.local_variables.append(variable_value)

    # Now set the locals as per the operands
    # Throw away 'extra' operands
    decoded_opers.pop(0)
    for index, operand in enumerate(decoded_opers):
      if index >= len(new_routine.local_variables):
        break
      new_routine.local_variables[index] = operand
    new_routine.called_arg_count = len(decoded_opers)

    # Finally, add the routine to the stack
    # and set the pc to the instruction after the header
    # and default local variables
    new_pc = routine_address + 1 + (2 * local_var_count)
    self.game.callRoutine(new_routine, new_pc)

  def jz(self):
      raise Exception("Unimplemented")
  def get_sibling(self):
      raise Exception("Unimplemented")
  def get_child(self):
      raise Exception("Unimplemented")
  def get_parent(self):
      raise Exception("Unimplemented")
  def get_prop_len(self):
      raise Exception("Unimplemented")
  def inc(self):
      raise Exception("Unimplemented")
  def dec(self):
      raise Exception("Unimplemented")
  def print_addr(self):
      raise Exception("Unimplemented")
  def remove_obj(self):
      raise Exception("Unimplemented")
  def print_obj(self):
      raise Exception("Unimplemented")
  def ret(self):
      raise Exception("Unimplemented")
  def ret_popped(self):
      raise Exception("Unimplemented")
  def jump(self):
      raise Exception("Unimplemented")
  def print_paddr(self):
      raise Exception("Unimplemented")
  def load(self):
      raise Exception("Unimplemented")
  def rtrue(self):
      raise Exception("Unimplemented")
  def rfalse(self):
      raise Exception("Unimplemented")
  def print_1(self):
      raise Exception("Unimplemented")
  def print_ret(self):
      raise Exception("Unimplemented")
  def save(self):
      raise Exception("Unimplemented")
  def restore(self):
      raise Exception("Unimplemented")
  def restart(self):
      raise Exception("Unimplemented")
  def quit(self):
      raise Exception("Unimplemented")
  def new_line(self):
      raise Exception("Unimplemented")
  def verify(self):
      raise Exception("Unimplemented")
  def storew(self):
      raise Exception("Unimplemented")
  def storeb(self):
      raise Exception("Unimplemented")
  def put_prop(self):
      raise Exception("Unimplemented")
  def read(self):
      raise Exception("Unimplemented")
  def print_char(self):
      raise Exception("Unimplemented")
  def print_num(self):
      raise Exception("Unimplemented")
  def random(self):
      raise Exception("Unimplemented")
  def push(self):
      raise Exception("Unimplemented")
  def pull(self):
      raise Exception("Unimplemented")

  def populateOpcodeMap(game):
    Instruction.opcodeMap[Operand.TwoOP] = {}
    Instruction.opcodeMap[Operand.TwoOP][0x1] = ("je", Instruction.je)
    Instruction.opcodeMap[Operand.TwoOP][0x2] = ("jl", Instruction.jl)
    Instruction.opcodeMap[Operand.TwoOP][0x3] = ("jg", Instruction.jg)
    Instruction.opcodeMap[Operand.TwoOP][0x4] = ("dec_chk", Instruction.dec_chk)
    Instruction.opcodeMap[Operand.TwoOP][0x5] = ("inc_chk", Instruction.inc_chk)
    Instruction.opcodeMap[Operand.TwoOP][0x6] = ("jin", Instruction.jin)
    Instruction.opcodeMap[Operand.TwoOP][0x7] = ("test", Instruction.test)
    Instruction.opcodeMap[Operand.TwoOP][0x8] = ("or", Instruction.or_1)
    Instruction.opcodeMap[Operand.TwoOP][0x9] = ("and", Instruction.and_1)
    Instruction.opcodeMap[Operand.TwoOP][0xa] = ("test_attr", Instruction.test_attr)
    Instruction.opcodeMap[Operand.TwoOP][0xb] = ("set_attr", Instruction.set_attr)
    Instruction.opcodeMap[Operand.TwoOP][0xc] = ("clear_attr", Instruction.clear_attr)
    Instruction.opcodeMap[Operand.TwoOP][0xd] = ("store", Instruction.store)
    Instruction.opcodeMap[Operand.TwoOP][0xe] = ("insert_obj", Instruction.insert_obj)
    Instruction.opcodeMap[Operand.TwoOP][0xf] = ("loadw", Instruction.loadw)
    Instruction.opcodeMap[Operand.TwoOP][0x10] = ("loadb", Instruction.loadb)
    Instruction.opcodeMap[Operand.TwoOP][0x11] = ("get_prop", Instruction.get_prop)
    Instruction.opcodeMap[Operand.TwoOP][0x12] = ("get_prop_addr", Instruction.get_prop_addr)
    Instruction.opcodeMap[Operand.TwoOP][0x13] = ("get_next_prop", Instruction.get_next_prop)
    Instruction.opcodeMap[Operand.TwoOP][0x14] = ("add", Instruction.add)
    Instruction.opcodeMap[Operand.TwoOP][0x15] = ("sub", Instruction.sub)
    Instruction.opcodeMap[Operand.TwoOP][0x16] = ("mul", Instruction.mul)
    Instruction.opcodeMap[Operand.TwoOP][0x17] = ("div", Instruction.div)
    Instruction.opcodeMap[Operand.TwoOP][0x18] = ("mod", Instruction.mod)
    Instruction.opcodeMap[Operand.TwoOP][0x19] = ("call_2s", Instruction.call)
    Instruction.opcodeMap[Operand.TwoOP][0x1A] = ("call_2n", Instruction.call)
    Instruction.opcodeMap[Operand.TwoOP][0x1B] = ("set_colour", Instruction.set_colour)
    Instruction.opcodeMap[Operand.TwoOP][0x1C] = ("throw", Instruction.throw)

    Instruction.opcodeMap[Operand.OneOP] = {}
    Instruction.opcodeMap[Operand.OneOP][0x0] = ("jz", Instruction.jz)
    Instruction.opcodeMap[Operand.OneOP][0x1] = ("get_sibling", Instruction.get_sibling)
    Instruction.opcodeMap[Operand.OneOP][0x2] = ("get_child", Instruction.get_child)
    Instruction.opcodeMap[Operand.OneOP][0x3] = ("get_parent", Instruction.get_parent)
    Instruction.opcodeMap[Operand.OneOP][0x4] = ("get_prop_len", Instruction.get_prop_len)
    Instruction.opcodeMap[Operand.OneOP][0x5] = ("inc", Instruction.inc)
    Instruction.opcodeMap[Operand.OneOP][0x6] = ("dec", Instruction.dec)
    Instruction.opcodeMap[Operand.OneOP][0x7] = ("print_addr", Instruction.print_addr)
    Instruction.opcodeMap[Operand.OneOP][0x8] = ("call_1s", Instruction.call)
    Instruction.opcodeMap[Operand.OneOP][0x9] = ("remove_obj", Instruction.remove_obj)
    Instruction.opcodeMap[Operand.OneOP][0xa] = ("print_obj", Instruction.print_obj)
    Instruction.opcodeMap[Operand.OneOP][0xb] = ("ret", Instruction.ret)
    Instruction.opcodeMap[Operand.OneOP][0xc] = ("jump", Instruction.jump)
    Instruction.opcodeMap[Operand.OneOP][0xd] = ("print_paddr", Instruction.print_paddr)
    Instruction.opcodeMap[Operand.OneOP][0xe] = ("load", Instruction.load)
    if game.version < 5:
      Instruction.opcodeMap[Operand.OneOP][0xf] = ("not", Instruction.not_1)
    else:
      Instruction.opcodeMap[Operand.OneOP][0xf] = ("call_1n", Instruction.call)

    Instruction.opcodeMap[Operand.ZeroOP] = {}
    Instruction.opcodeMap[Operand.ZeroOP][0x0] = ("rtrue", Instruction.rtrue)
    Instruction.opcodeMap[Operand.ZeroOP][0x1] = ("rfalse", Instruction.rfalse)
    Instruction.opcodeMap[Operand.ZeroOP][0x2] = ("print", Instruction.print_1)
    Instruction.opcodeMap[Operand.ZeroOP][0x3] = ("print_ret", Instruction.print_ret)
    Instruction.opcodeMap[Operand.ZeroOP][0x4] = ("nop", Instruction.nop)
    if game.version < 4:
      Instruction.opcodeMap[Operand.ZeroOP][0x5] = ("save1", Instruction.save)
    else:
      Instruction.opcodeMap[Operand.ZeroOP][0x5] = ("save4", Instruction.save)
    if game.version < 4:
      Instruction.opcodeMap[Operand.ZeroOP][0x6] = ("restore1", Instruction.restore)
    else:
      Instruction.opcodeMap[Operand.ZeroOP][0x6] = ("restore4", Instruction.restore)
    Instruction.opcodeMap[Operand.ZeroOP][0x7] = ("restart", Instruction.restart)
    Instruction.opcodeMap[Operand.ZeroOP][0x8] = ("ret_popped", Instruction.ret_popped)
    if game.version < 5:
      Instruction.opcodeMap[Operand.ZeroOP][0x9] = ("pop", Instruction.pop)
    else:
      Instruction.opcodeMap[Operand.ZeroOP][0x9] = ("catch", Instruction.catch)
    Instruction.opcodeMap[Operand.ZeroOP][0xa] = ("quit", Instruction.quit)
    Instruction.opcodeMap[Operand.ZeroOP][0xb] = ("new_line", Instruction.new_line)
    Instruction.opcodeMap[Operand.ZeroOP][0xc] = ("show_status", Instruction.show_status)
    Instruction.opcodeMap[Operand.ZeroOP][0xd] = ("verify", Instruction.verify)
    Instruction.opcodeMap[Operand.ZeroOP][0xf] = ("piracy", Instruction.piracy)

    Instruction.opcodeMap[Operand.VAR] = {}
    Instruction.opcodeMap[Operand.VAR][224] = ("call", Instruction.call)
    Instruction.opcodeMap[Operand.VAR][225] = ("storew", Instruction.storew)
    Instruction.opcodeMap[Operand.VAR][226] = ("storeb", Instruction.storeb)
    Instruction.opcodeMap[Operand.VAR][227] = ("put_prop", Instruction.put_prop)
    if game.version < 5:
      Instruction.opcodeMap[Operand.VAR][228] = ("read", Instruction.read)
    else:
      Instruction.opcodeMap[Operand.VAR][228] = ("read5", Instruction.read)
    Instruction.opcodeMap[Operand.VAR][229] = ("print_char", Instruction.print_char)
    Instruction.opcodeMap[Operand.VAR][230] = ("print_num", Instruction.print_num)
    Instruction.opcodeMap[Operand.VAR][231] = ("random", Instruction.random)
    Instruction.opcodeMap[Operand.VAR][232] = ("push", Instruction.push)
    Instruction.opcodeMap[Operand.VAR][233] = ("pull", Instruction.pull)
    Instruction.opcodeMap[Operand.VAR][234] = ("split_window", Instruction.split_window)
    Instruction.opcodeMap[Operand.VAR][235] = ("set_window", Instruction.set_window)
    Instruction.opcodeMap[Operand.VAR][236] = ("call_vs2", Instruction.call)
    Instruction.opcodeMap[Operand.VAR][237] = ("erase_window", Instruction.erase_window)
    Instruction.opcodeMap[Operand.VAR][238] = ("erase_line", Instruction.erase_line)
    Instruction.opcodeMap[Operand.VAR][239] = ("set_cursor", Instruction.set_cursor)
    Instruction.opcodeMap[Operand.VAR][240] = ("get_cursor", Instruction.get_cursor)
    Instruction.opcodeMap[Operand.VAR][241] = ("set_text_style", Instruction.set_text_style)
    Instruction.opcodeMap[Operand.VAR][242] = ("buffer_mode", Instruction.buffer_mode)
    Instruction.opcodeMap[Operand.VAR][243] = ("output_stream", Instruction.output_stream)
    Instruction.opcodeMap[Operand.VAR][244] = ("input_stream", Instruction.input_stream)
    Instruction.opcodeMap[Operand.VAR][245] = ("sound_effect", Instruction.sound_effect)
    Instruction.opcodeMap[Operand.VAR][246] = ("read_char", Instruction.read_char)
    Instruction.opcodeMap[Operand.VAR][247] = ("scan_table", Instruction.scan_table)
    Instruction.opcodeMap[Operand.VAR][248] = ("not", Instruction.not_1)
    Instruction.opcodeMap[Operand.VAR][249] = ("call_vn", Instruction.call)
    Instruction.opcodeMap[Operand.VAR][250] = ("call_vn2", Instruction.call)
    Instruction.opcodeMap[Operand.VAR][251] = ("tokenise", Instruction.tokenise)
    Instruction.opcodeMap[Operand.VAR][252] = ("encode_text", Instruction.encode_text)
    Instruction.opcodeMap[Operand.VAR][253] = ("copy_table", Instruction.copy_table)
    Instruction.opcodeMap[Operand.VAR][254] = ("print_table", Instruction.print_table)
    Instruction.opcodeMap[Operand.VAR][255] = ("check_arg_count", Instruction.check_arg_count)

    Instruction.opcodeMap["EXT"] = {}
    Instruction.opcodeMap["EXT"][0x0] = ("save4", Instruction.save)
    Instruction.opcodeMap["EXT"][0x1] = ("restore4", Instruction.restore)
    Instruction.opcodeMap["EXT"][0x2] = ("log_shift", Instruction.log_shift)
    Instruction.opcodeMap["EXT"][0x3] = ("art_shift", Instruction.art_shift)
    Instruction.opcodeMap["EXT"][0x4] = ("set_font", Instruction.set_font)
    Instruction.opcodeMap["EXT"][0x9] = ("save_undo", Instruction.save_undo)
    Instruction.opcodeMap["EXT"][0xA] = ("restore_undo", Instruction.restore_undo)

def main():
  # Load up the game
  f = open(sys.argv[1], "rb")
  raw_memory = f.read()
  main_memory = Memory(raw_memory)

  display = Display()
  display.stdscr = curses.initscr()
  curses.start_color()
  curses.noecho()
  curses.cbreak()
  display.stdscr.clear()
  display.stdscr.idlok(True)
  display.stdscr.scrollok(True)
  y, x = display.stdscr.getmaxyx()


  game = Game(main_memory, display)
  Instruction.populateOpcodeMap(game)
  # Set the initial cursor position
  #game.display.bottomWinCursor = (y-1, 0)
  #game.setScreenDimensions()
  game.loop()

if __name__ == "__main__":
  try:
    main()
  finally:
    # Try and save the terminal from a hideous fate!
    curses.nocbreak()
    curses.echo()
    curses.endwin()
