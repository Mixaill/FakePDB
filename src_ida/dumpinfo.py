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

def processSegments():
    segments = list()
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if seg:
            segm = dict()
            segm['name'] = ida_segment.get_segm_name(seg)
            segm['start_ea'] = seg.start_ea  
            segm['class'] = ida_segment.get_segm_class(seg)
            segments.append(segm)

    return segments
    
def processFunctions():
    functions = list()

    start = ida_ida.cvar.inf.min_ea
    end = ida_ida.cvar.inf.max_ea

    # find first function head chunk in the range
    chunk = ida_funcs.get_fchunk(start)
    if not chunk:
        chunk = ida_funcs.get_next_fchunk(start)
    while chunk and chunk.start_ea < end and (chunk.flags & ida_funcs.FUNC_TAIL) != 0:
        chunk = ida_funcs.get_next_fchunk(chunk.start_ea)
    func = chunk

    while func and func.start_ea < end:
        function = dict()

        flags = ida_bytes.get_full_flags(func.start_ea)

        function['start_ea'] = func.start_ea
        function['name'] = ida_funcs.get_func_name(func.start_ea)
        function['is_public'] = ida_name.is_public_name(func.start_ea)
        function['is_autonamed'] = flags & ida_bytes.FF_LABL != 0

        functions.append(function)

        func = ida_funcs.get_next_func(func.start_ea)

    return functions


def processNames():
    names = list()

    for i in xrange(ida_name.get_nlist_size()):
        name = dict()
        name['ea']   = ida_name.get_nlist_ea(i)
        name['name'] = ida_name.get_nlist_name(i)
        name['is_public'] = ida_name.is_public_name(name['ea'])
        name['is_func'] = ida_funcs.get_func(name['ea']) is not None

        names.append(name)

    return names

def main():
    filepath = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    pre, ext = os.path.splitext(filepath)
    filepath = pre + ".json"

    output = dict()
    output['segments'] = processSegments()
    output['functions'] = processFunctions()
    output['names'] = processNames()

    with open(filepath, "w") as f:
        json.dump(output, f, indent=4)


ida_auto.set_ida_state(IDA_STATUS_WORK)
main()
ida_auto.set_ida_state(IDA_STATUS_READY)
