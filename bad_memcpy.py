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
sinks = [
    'acosNvramConfig_get'
]

bitness_masks = {
    '16': 0xffff,
    '32': 0xffffffff,
    '64': 0xffffffffffffffff,
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
def visit_call(func,fm,op):
    opinputs = op.getInputs()
    call_target_addr = opinputs[0].getAddress()
    call_target_func = fm.getFunctionAt(call_target_addr)


    if call_target_func.name in sinks:
        print("\t\tFound sink: " + call_target_func.name)
        offset = opinputs[1].getOffset()
        print((getUniqueAddress(offset)))
        exit(0)
        
        
        

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