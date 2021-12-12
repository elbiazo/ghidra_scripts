#@author Biazo
#@category VR
#@keybinding 
#@menupath 
#@toolbar 
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import VarnodeAST
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.program.model.pcode import HighLocal
from ghidra.program.model.pcode import HighSymbol
from ghidra.program.util import SymbolicPropogator
from ghidra.program.model.pcode import PcodeOp, VarnodeTranslator
from ghidra.program.flatapi import FlatProgramAPI
sinks = [
    'acosNvramConfig_get'
]

bitness_masks = {
    '16': 0xffff,
    '32': 0xffffffff,
    '64': 0xffffffffffffffff,
}

BINARY_PCODE_OPS = {
    PcodeOp.INT_ADD: '+', 
    PcodeOp.PTRSUB: '+', 
    PcodeOp.INT_SUB: '-', 
    PcodeOp.INT_MULT: '*'
}

cp = currentProgram
fp = FlatProgramAPI(cp)
space_ram = None
space_uniq = None


name2space = {
    'register': {},
    'unique': {}
}

def get_high_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    res = ifc.decompileFunction(func, 60, monitor)
    return res.getHighFunction()

def get_calling_function(func):
    monitor = ConsoleTaskMonitor()
    called_funcs = func.getCallingFunctions(monitor)
    return called_funcs

def get_varnode_value(varnode):
    space_name = varnode.getAddress().addressSpace.name
    offset = varnode.offset
    addr = fp.toAddr(offset)

    global space_ram
    if space_ram is None and space_name == 'ram':
        space_ram = varnode.space

    global space_uniq
    if space_uniq is None and space_name == 'unique':
        space_uniq = varnode.space

    if space_name == 'const':
        size = varnode.size
        return offset
    
    elif space_name == 'ram':
        if is_address_in_current_program(addr):
            return get_value_from_addr(addr, varnode.size)
        return None

    if space_name in name2space and offset in name2space[space_name] and name2space[space_name][offset] is not None:
        return name2space[space_name][offset]

    if space_name == 'register':
        translator = VarnodeTranslator(cp)
        reg = translator.getRegister(varnode)
        if reg is not None:
            return str(reg.name)

    else:
        # NOTE: It looks like definition is always null without the decompiler? Investigate, Sam. Just kidding, I know
        # you won't.
        defn = varnode.getDef()
        return get_pcode_value(defn)
    
def get_stack_var_from_varnode(func, varnode):
    if type(varnode) not in [Varnode, VarnodeAST]:
        raise Exception("Invalid value passed to get_stack_var_from_varnode(). Expected `Varnode` or `VarnodeAST`, got {}.".format(type(varnode)))
    
    bitmask = bitness_masks[currentProgram.getMetadata()['Address Size']]

    local_variables = func.getAllVariables()
    vndef = varnode.getDef()
    if vndef:
        vndef_inputs = vndef.getInputs()
        for defop_input in vndef_inputs:
            defop_input_offset = defop_input.getAddress().getOffset() & bitmask
            for lv in local_variables:
                unsigned_lv_offset = lv.getMinAddress().getUnsignedOffset() & bitmask
                if unsigned_lv_offset == defop_input_offset:
                    return lv
        
        # If we get here, varnode is likely a "acStack##" variable.
        hf = get_high_function(func)
        lsm = hf.getLocalSymbolMap()

        for vndef_input in vndef_inputs:
            defop_input_offset = vndef_input.getAddress().getOffset() & bitmask
            for symbol in lsm.getSymbols():
                if symbol.isParameter(): 
                    continue
                if defop_input_offset == symbol.getStorage().getFirstVarnode().getOffset() & bitmask:
                    return symbol

    # unable to resolve stack variable for given varnode
    return None

def getUniqueAddress(offset):
    return currentProgram.getAddressFactory().getUniqueSpace().getAddress(offset)

def getRAMAddress(offset):
    return currentProgram.getAddressFactory().getAddress(offset)

def get_pcode_value(pcode):
    '''
    Get the value of a pcode operation. Will recursively call `get_varnode_value` on the
    operation's operands.
    '''

    # Something might've gone wrong while backtracking (e.g. an unimplemented opcode)
    # so pcode could be None.

    if pcode is None:
        return None

    opcode = pcode.getOpcode()

    if opcode in BINARY_PCODE_OPS:
        op1 = get_varnode_value(pcode.getInput(0))
        op2 = get_varnode_value(pcode.getInput(1))

        if op1 is None or op2 is None:
            return None

        oper = BINARY_PCODE_OPS[opcode]

        # get_varnode_value can return an integer or a string
        if type(op1) == str or type(op2) == str or type(op1) == unicode or type(op2) == unicode:
            op1 = str(op1)
            op2 = str(op2)

            if '+' in op1 and op2.isdigit():
                op1, op3 = tuple(op1.split('+'))
                op2 = eval('%s %s %s' % (op3, oper, op2))
            elif '-' in op1 and op2.isdigit():
                op1, op3 = op1[:op1.index('-')], op1[op1.index('-')+1:]
                op2 = eval('%s %s %s' % (op3, oper, op2))

            return '%s%s%s' % (op1, oper, op2)
        else:
            return eval('%d %s %d' % (op1, oper, op2))

    elif opcode == PcodeOp.PTRADD:
        op1 = get_varnode_value(pcode.getInput(0))
        op2 = get_varnode_value(pcode.getInput(1))
        op3 = get_varnode_value(pcode.getInput(2))

        if op1 is None or op2 is None or op3 is None:
            return None

        return op1 + op2 * op3

    elif opcode == PcodeOp.INT_2COMP:
        op = get_varnode_value(pcode.getInput(0))

        if op is None:
            return None

        return -op

    elif opcode == PcodeOp.COPY or opcode == PcodeOp.CAST:
        return get_varnode_value(pcode.getInput(0))

    elif opcode == PcodeOp.INDIRECT:
        # TODO: Figure out what exactly the indirect operator means and how to deal with it more precisely
        return get_varnode_value(pcode.getInput(0))

    elif opcode == PcodeOp.MULTIEQUAL:
        # TODO: Handle multiequal for actual multiple-possible values.
        #
        # Currently, this case is just meant to handle when Ghidra produces a Pcode op like:
        #       v1 = MULTIEQUAL(v1, v1)
        # for some reason. In this case, it's just the identity.
        op1 = pcode.getInput(0)

        for i in range(1, pcode.numInputs):
            opi = pcode.getInput(i)

            if op1.space != opi.space or op1.offset != opi.offset or op1.size != opi.size:
                print('Unhandled multiequal on differing inputs: %s' % pcode)
                return None

        return get_varnode_value(op1)

    elif opcode == PcodeOp.LOAD:
        off = get_varnode_value(pcode.getInput(1))
        if off is None or type(off) == str:
            return None

        addr = fp.toAddr(off)
        if addr is None:
            return None

        space = pcode.getInput(0).offset

        # The offset of the space input specifies the address space to load from.
        # Right now, we're only handling loads from RAM

        if space_ram is not None and space == space_ram:
            try:
                return get_value_from_addr(addr, pcode.output.size)
            except MemoryAccessException:
                return None
        else:
            #print('Unhandled load space %d for pcode %s' % (space, pcode))
            return None

    #print('Unhandled pcode opcode %s pcode %s' % (pcode.getMnemonic(opcode), pcode))
    return None
    

def visit_call(func,fm,op):
    opinputs = op.getInputs()
    call_target_addr = opinputs[0].getAddress()
    call_target_func = fm.getFunctionAt(call_target_addr)

    if call_target_func.name in sinks:
        print("\t\tFound sink: " + call_target_func.name)
        offset = opinputs[1].getOffset()
        print(opinputs[1].getDef())
        print(hex(get_pcode_value(opinputs[1].getDef())))
        ram_addr = get_pcode_value(opinputs[1].getDef())
        str_addr =getRAMAddress(hex(int(ram_addr)))
        print(getDataAt(str_addr))

        
        

def main():
    fm = currentProgram.getFunctionManager()
    funcs = [func for func in fm.getFunctions(True)]

    interesting_funcs = []
    for func in funcs:
        if func.name in sinks:
            interesting_funcs.append(func)

    called_funcs = []
    for func in interesting_funcs:
        called_funcs.extend(get_calling_function(func))
    
    clean_called_funcs = []
    for func in called_funcs:
        if func.name not in sinks:
            clean_called_funcs.append(func)
            

    for func in clean_called_funcs:
        print("\nAnalyzing function: " + func.name)
        hf = get_high_function(func)
        opiter = hf.getPcodeOps()

        while opiter.hasNext():
            op = next(opiter)
            menmonic = op.getMnemonic()
            if menmonic == 'CALL':
                visit_call(func, fm,op)
            

main()