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


def match_pattern(ea):

    for pattern in junk_patterns:
        # create blank opcode tuple for comparison
        opcode_bytes = []
        opcode_iterator = ea
        for byte in pattern['pattern']:
            opcode_bytes.append(get_byte(opcode_iterator))
            opcode_iterator += 1
        if opcode_bytes == pattern['pattern']:
            return pattern

    return None

def patch_db(ea, pattern):
    opcode_iterator = ea
    for byte in pattern['fillwith']:
        put_byte(opcode_iterator, byte)
        opcode_iterator += 1




def dejunk_selection():
    selection_start = SelStart()
    selection_end = SelEnd()
    selection_size = selection_end - selection_start
    print "Dejunking %X - %X" % (selection_start, selection_end)
    dejunk(selection_start, selection_end)
    do_unknown_range(selection_start, selection_size, DOUNK_SIMPLE)
    analyze_area(selection_start, selection_end)
    

def dejunk(ea_start, ea_end):
    junk_iterator = ea_start

    while junk_iterator != 0xFFFFFFFF:
        pattern = match_pattern(junk_iterator)
        if pattern != None:
            patch_db(junk_iterator, pattern)
        junk_iterator = next_head(junk_iterator, ea_end)

    return

