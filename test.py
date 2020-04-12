# Just test script
# @author Eric Biazo
# @category Memory
# @keybinding
# @menupath
# @toolbar

# Xors list with given xor value


def xor(data, xor_val):
    output = []
    for i in range(0, len(data)):
        output.append(data[i] ^ xor_val)
    return output


data_length = currentSelection.getFirstRange().getLength()
data_begin = currentSelection.getFirstRange().getMinAddress()

data = getBytes(data_begin, data_length)

output_list = []
for i in range(0, 255):
    output_list.append(xor(data, i))

for i in range(0, 255):
    print('Xor Val: ', i)
    print(''.join(chr(output_list[i][x] ^ 0xff) for x in range(0, len(data))))
    print("\n")
