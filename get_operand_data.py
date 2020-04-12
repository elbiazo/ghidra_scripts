#
#@author Eric Biazo
#@category memory
#@keybinding
#@menupath
#@toolbar

start_addr = currentAddress
end_addr = currentSelection.getFirstRange().getMaxAddress()
length = currentSelection.getFirstRange().getLength()

inst = getInstructionAt(start_addr)

if(not currentSelection.isEmpty()):
    output = []
    
    for i in range(0, 22):
        output.append(inst.getScalar(1))
        inst = inst.getNext()

    print(output)

result = []
for v in output:
    print(chr(v^0x29a))