# When you select two data from listing with same length, XOR it and give result in string
# @author Eric Biazo
# @category Memory
# @keybinding
# @menupath
# @toolbar


def xor(data_1, data_2, length):
    output = []
    for i in range(0, length):
        output.append(data_1[i] ^ data_2[i])

    return output


# If there is two selected data.
if(currentSelection.getNumAddressRanges() == 2):
    sel = currentSelection

    data_1_length = sel.getFirstRange().getLength()
    data_1_begin = sel.getFirstRange().getMinAddress()
    data_1 = getBytes(data_1_begin, data_1_length)

    data_2_length = sel.getLastRange().getLength()
    data_2_begin = sel.getLastRange().getMinAddress()
    data_2 = getBytes(data_2_begin, data_2_length)

    if(data_1_length == data_2_length):
        out = xor(data_1, data_2, data_1_length)
        str_out = ''.join("{:c}".format(x) for x in out)
        print(str_out)
    else:
        print("Two data selected doesn't have same length!")
else:
    print("Select two data to XOR")

