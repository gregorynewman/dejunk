# dejunk.py
#
# Gregory Newman (gregory.e.newman@gmail.com)

from idaapi import *

junk_patterns = [
        {
            'pattern':[0xF2,0xEB],
            'fillwith':[0x90,0xEB],
        },
        {
            'pattern':[0xF3, 0xEB],
            'fillwith':[0x90, 0xEB],
        },
        {
            'pattern':[0x65,0xEB],
            'fillwith':[0x90,0xEB],
        },
        {
            'pattern':[0x64, 0xEB],
            'fillwith':[0x90, 0xEB],
        },
        {
            'pattern':[0x36,0xEB],
            'fillwith':[0x90,0xEB],
        },
        {
            'pattern':[0x3E, 0xEB],
            'fillwith':[0x90, 0xEB],
        },
        {
            'pattern':[0x26,0xEB],
            'fillwith':[0x90,0xEB],
        },
        {
            'pattern':[0x2E, 0xEB],
            'fillwith':[0x90, 0xEB],
        }, 
    ]

end_patterns = [
        [0xC3],
        [0xC2,'??','??'],
    ]


def match_pattern(ea):

    for pattern in junk_patterns:
        # create blank opcode list for comparison
        opcode_bytes = []
        opcode_iterator = ea
        for byte in pattern['pattern']:
            if byte == '??':
                opcode_bytes.append(byte) # wildcard byte doesn't mater so append wildcard for matching
                continue
            opcode_bytes.append(get_byte(opcode_iterator))
            opcode_iterator += 1
        if opcode_bytes == pattern['pattern']:
            return pattern

    return None

def match_end(ea):
    for pattern in end_patterns:
        opcode_bytes = []
        opcode_iterator = ea
        for byte in pattern:
            if byte == '??':
                opcode_bytes.append(byte) # wildcard byte doesn't matter so append wildcard for matching
                continue
            opcode_bytes.append(get_byte(opcode_iterator))
            opcode_iterator += 1
        if opcode_bytes == pattern:
            return True

    return False

def patch_db(ea, pattern):
    opcode_iterator = ea
    for byte in pattern['fillwith']:
        put_byte(opcode_iterator, byte)
        opcode_iterator += 1

# max_size is set to 1024 to avoid excessive dejunking or not finding any end
def find_end(ea, max_size=0x400):
    iterator = ea
    ea_end = ea+max_size
    while iterator != 0xFFFFFFFF:
        if match_end(iterator) == True:
            return iterator
        iterator = next_head(iterator, ea_end)

    return False


def dejunk_selection():
    selection_start = SelStart()
    selection_end = SelEnd()
    selection_size = selection_end - selection_start
    print "Dejunking %X - %X" % (selection_start, selection_end)
    dejunk(selection_start, selection_end)
    do_unknown_range(selection_start, selection_size, DOUNK_SIMPLE) # un-analyze code
    auto_make_code(selection_start, selection_end) # re-analyze to reflect patches

def dejunk_until_end():
    ea_start = get_screen_ea()
    ea_end = find_end(ea_start)
    print "Dejunking %X - %X" % (ea_start, ea_end)
    dejunk(ea_start, ea_end)
    do_unknown_range(ea_start, ea_end, DOUNK_SIMPLE) # un-analyze code
    auto_make_code(ea_start, ea_end) # re-analyze to reflect patches
    

def dejunk(ea_start, ea_end):
    junk_iterator = ea_start

    while junk_iterator != 0xFFFFFFFF:
        pattern = match_pattern(junk_iterator)
        if pattern != None:
            patch_db(junk_iterator, pattern)
        junk_iterator = next_head(junk_iterator, ea_end)

    return

