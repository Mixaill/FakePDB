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
import ida_segment
import ida_typeinf


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
                'class'    : ida_segment.get_segm_class(seg)
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
        
        flags = ida_bytes.get_full_flags(start_ea)

        function = {
            'start_ea'     : start_ea,
            'name'         : ida_funcs.get_func_name(start_ea),
            'is_public'    : ida_name.is_public_name(start_ea),
            'is_autonamed' : flags & ida_bytes.FF_LABL != 0
        }

        processFunctionTypeinfo(function)

        functions.append(function)

        func = ida_funcs.get_next_func(start_ea)

    return functions


def processNames():
    names = list()

    for i in xrange(ida_name.get_nlist_size()):
        ea = ida_name.get_nlist_ea(i)
        
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
    filepath = pre + ".json"

    output = {
        'segments'  : processSegments(),
        'functions' : processFunctions(),
        'names'     : processNames()
    }

    with open(filepath, "w") as f:
        json.dump(output, f, indent=4)


ida_auto.set_ida_state(IDA_STATUS_WORK)
main()
ida_auto.set_ida_state(IDA_STATUS_READY)
