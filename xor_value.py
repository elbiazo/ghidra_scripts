# Xor the selected string with value you input.
# @author Eric Biazo
# @category Memory
# @keybinding
# @menupath
# @toolbar


def xor(data, xor_value):
    output = []
    for i in range(0, 18):
        output.append((data[i]) ^ xor_value)
    return output


data = [-24, -34, -2, -1, -1, -119, -63, -70, -
        125, 32, 8, -126, -119, -56, -9, -22, -115, 4]

output_array = []

for i in range(0, 256):
    output_array.append(xor(data, 0x68))

print(output_array[1])
for i in range(0, 18):
    str_out = ''.join(chr(x) for x in output_array[i])
    print(str_out)
