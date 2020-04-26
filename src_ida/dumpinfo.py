"""
   Copyright 2019 Mikhail Paulyshka

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import json
import os.path

import ida_auto
import ida_bytes
import ida_funcs
import ida_loader
import ida_nalt
import ida_name
import ida_ida
import ida_idaapi
import ida_search
import ida_segment
import ida_typeinf
import ida_ua
import ida_xref

#
# OPTIONS
#

SIGNSEARCH_ENABLE    = False         # enable signature search
SIGNSEARCH_ENABLE_AUTONAMED = False  # search signature for autonamed functions
SIGNSEARCH_MINLENGTH = 1             # minimal length of signature
SIGNSEARCH_FILTER = ''               # filter by name (function name should contains this substring)


#
# signatures search
#

def signature_add_bytes(bytes_ea, bytes_count):
    sginature_str = ''
    for i in xrange(bytes_count):
        sginature_str = sginature_str + '%02X ' % ida_bytes.get_byte(bytes_ea + i)
    
    return sginature_str

def signature_add_placeholders(count):
    return '? ' * count

def signature_search_rescount(sig): 
    search_addr = ida_ida.cvar.inf.min_ea
    search_results = 0

    while search_results < 2:
        search_addr = ida_search.find_binary(search_addr, ida_ida.cvar.inf.max_ea, sig, 16, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
        if search_addr == ida_idaapi.BADADDR:
            break
        search_results += 1

    return search_results

def signature_check_xrefs(instruction):
    if ida_xref.get_first_dref_from(instruction.ea) != ida_idaapi.BADADDR:
        return True
    if ida_xref.get_first_fcref_from(instruction.ea) != ida_idaapi.BADADDR:
        return True
    return False

def signature_get_value_offset(instruction):
    for i in xrange(ida_ida.UA_MAXOP):
        if instruction.Operands[i].offb != 0:
            return instruction.Operands[i].offb

    return 0

def signature_add_instruction(instruction):
    strSig = ''
    
    value_offset = signature_get_value_offset(instruction)
    
    #in case of no instruction value, just add al the bytes
    if value_offset == 0:
        return signature_add_bytes(instruction.ea, instruction.size)
    
    #in other case, add instruction
    strSig += signature_add_bytes(instruction.ea, value_offset)

    #and then add bytes if there is no xref, or add placeholders if xrefs found
    if signature_check_xrefs(instruction):
        strSig += signature_add_placeholders(instruction.size - value_offset)
    else:
        strSig += signature_add_bytes(instruction.ea + value_offset, instruction.size - value_offset)

    return strSig

def signature_get_function_sig(func_ea, func_name, func_autonamed):

    if func_autonamed and not SIGNSEARCH_ENABLE_AUTONAMED:
        return ''

    if SIGNSEARCH_FILTER and not SIGNSEARCH_FILTER in func_name:
        return ''
        
    signature_str = ''
    current_addr = func_ea
    while True:
        instruction  = ida_ua.insn_t()
        instruction_len = ida_ua.decode_insn(instruction, current_addr)
        if not instruction_len:
            return ''

        signature_str += signature_add_instruction(instruction)

        if current_addr - func_ea >= SIGNSEARCH_MINLENGTH:
            rescount = signature_search_rescount(signature_str)
            if rescount == 0:
                return ''

            if rescount == 1:
                break

        current_addr = current_addr + instruction_len

    return signature_str.strip()


#
# general
#

def processGaneral():
    result = dict()

    result['filename'] = ida_nalt.get_root_filename()

    return result


def describe_callingconvention(cc):
    #https://www.hex-rays.com/products/ida/support/sdkdoc/group___c_m___c_c__.html
    if cc == 0x00:
        return 'invalid'
    elif cc == 0x10:
        return 'unknown'
    elif cc == 0x20:
        return 'voidarg'
    elif cc == 0x30:
        return 'cdecl'
    elif cc == 0x40:
        return 'cdecl_ellipsis'
    elif cc == 0x50:
        return 'stdcall'
    elif cc == 0x60:
        return 'pascal'
    elif cc == 0x70:
        return 'fastcall'
    elif cc == 0x80:
        return 'thiscall'
    elif cc == 0x90:
        return 'manual'
    elif cc == 0xA0:
        return 'spoiled'
    elif cc == 0xB0:
        return 'reserved'
    elif cc == 0xC0:
        return 'reserved'
    elif cc == 0xD0:
        return 'special_ellipsis'
    elif cc == 0xE0:
        return 'special_pstack'
    elif cc == 0xF0:
        return 'special'

    return None
        

def describe_argloc(location):
    #https://www.hex-rays.com/products/ida/support/sdkdoc/group___a_l_o_c__.html
    if   location == 0:
        return 'none'
    elif location == 1:
        return 'stack'
    elif location == 2:
        return 'distributed'
    elif location == 3:
        return 'register_one'
    elif location == 4:
        return 'register_pair'
    elif location == 5:
        return 'register_relative'
    elif location == 6:
        return 'global_address'
    else:
        return 'custom'
    
    return None


def processSegments():
    segments = list()
    
    for n in xrange(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if seg:
            segm = {
                'name'     : ida_segment.get_segm_name(seg),
                'start_ea' : seg.start_ea,
                'class'    : ida_segment.get_segm_class(seg),
                'selector' : seg.sel
            }
            
            segments.append(segm)

    return segments

def processFunctionTypeinfo(function):

    tinfo = ida_typeinf.tinfo_t()
    func_type_data = ida_typeinf.func_type_data_t()
    tinfo.get_named_type
    ida_typeinf.guess_tinfo(function['start_ea'],tinfo)
    tinfo.get_func_details(func_type_data)

    #calling convention
    function['calling_convention'] = describe_callingconvention(func_type_data.cc)
    func_type_data.rettype
    
    #return tpye
    function['return_type'] = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, func_type_data.rettype, '', '')

    #arguments
    arguments = list()
    
    for funcarg in func_type_data:
        arginfo = {
            'name'              : funcarg.name,
            'type'              : ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, funcarg.type, '', ''),
            'argument_location' : describe_argloc(funcarg.argloc.atype())
        }
        
        arguments.append(arginfo)

    function['arguments'] = arguments

def processFunctions():
    functions = list()

    start = ida_ida.cvar.inf.min_ea
    end   = ida_ida.cvar.inf.max_ea

    # find first function head chunk in the range
    chunk = ida_funcs.get_fchunk(start)
    
    if not chunk:
        chunk = ida_funcs.get_next_fchunk(start)
    while chunk and chunk.start_ea < end and (chunk.flags & ida_funcs.FUNC_TAIL) != 0:
        chunk = ida_funcs.get_next_fchunk(chunk.start_ea)
    
    func = chunk

    while func and func.start_ea < end:
        start_ea = func.start_ea
        
        func_flags = ida_bytes.get_full_flags(start_ea)
        func_name = ida_funcs.get_func_name(start_ea)
        func_autonamed = func_flags & ida_bytes.FF_LABL != 0

        function = {
            'start_ea'     : start_ea,
            'name'         : func_name,
            'is_public'    : ida_name.is_public_name(start_ea),
            'is_autonamed' : func_autonamed,
            'signature'    : signature_get_function_sig(start_ea, func_name, func_autonamed) if SIGNSEARCH_ENABLE else ''
        }

        processFunctionTypeinfo(function)

        functions.append(function)

        func = ida_funcs.get_next_func(start_ea)

    return functions


def processNames():
    names = list()

    for i in xrange(ida_name.get_nlist_size()):
        ea = ida_name.get_nlist_ea(i)
        if ida_funcs.get_func(ea) is not None:
            continue

        name = {
            'ea'        : ea,
            'name'      : ida_name.get_nlist_name(i),
            'is_public' : ida_name.is_public_name(ea),
            'is_func'   : ida_funcs.get_func(ea) is not None
        }

        names.append(name)

    return names

def main():
    filepath = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    pre, ext = os.path.splitext(filepath)
    filepath = pre + ".exe.json"

    output = {
        'general'   : processGaneral(), 
        'segments'  : processSegments(),
        'functions' : processFunctions(),
        'names'     : processNames()
    }

    with open(filepath, "w") as f:
        json.dump(output, f, indent=4)


ida_auto.set_ida_state(IDA_STATUS_WORK)
main()
ida_auto.set_ida_state(IDA_STATUS_READY)
