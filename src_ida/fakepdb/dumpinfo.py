"""
   Copyright 2020 Mikhail Paulyshka

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

from __future__ import print_function

import json
import os.path
import sys

if sys.version_info.major == 3:
    from past.builtins import xrange

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_loader
import ida_nalt
import ida_name
import ida_pro
import ida_segment
import ida_typeinf

class InformationDumper():
    def __init__(self):
        pass

    #
    # public
    #

    def dump_info(self, filepath):
        self._base = ida_nalt.get_imagebase()

        output = {
            'general'   : self.__process_general(), 
            'segments'  : self.__process_segments(),
            'functions' : self.__process_functions(),
            'names'     : self.__process_names()
        }

        with open(filepath, "w") as f:
            json.dump(output, f, indent=4)


    #
    # private
    #

    def __describe_argloc(self, location):
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

    def __describe_callingconvention(self, cc):
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

    def __process_general(self):
        result = dict()
        result['filename'] = ida_nalt.get_root_filename()
        return result

    def __process_segments(self):
        segments = list()

        for n in xrange(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if seg:
                segm = {
                    'name'      : ida_segment.get_segm_name(seg),
                    'start_rva' : seg.start_ea - self._base,
                    'class'     : ida_segment.get_segm_class(seg),
                    'selector'  : seg.sel
                }
                
                segments.append(segm)

        return segments

    def __process_function_typeinfo(self, info, func):

        tinfo = ida_typeinf.tinfo_t()
        func_type_data = ida_typeinf.func_type_data_t()
        if ida_pro.IDA_SDK_VERSION >= 740:
            ida_typeinf.guess_tinfo(tinfo,func.start_ea)
        else:
            ida_typeinf.guess_tinfo(func.start_ea,tinfo)
        tinfo.get_func_details(func_type_data)

        #calling convention
        info['calling_convention'] = self.__describe_callingconvention(func_type_data.cc)
        func_type_data.rettype
        
        #return tpye
        info['return_type'] = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, func_type_data.rettype, '', '')

        #arguments
        arguments = list()
        
        for funcarg in func_type_data:
            arginfo = {
                'name'              : funcarg.name,
                'type'              : ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, funcarg.type, '', ''),
                'argument_location' : self.__describe_argloc(funcarg.argloc.atype())
            }
            
            arguments.append(arginfo)

        info['arguments'] = arguments

    def __process_function_labels(self, func):
        labels = list()

        it = ida_funcs.func_item_iterator_t()
        if not it.set(func):
            return labels

        while it.next_code():
            ea = it.current()
            name = ida_name.get_visible_name(ea, ida_name.GN_LOCAL)

            if name != '':
                labels.append({
                    'offset'       : ea - func.start_ea,
                    'name'         : name,
                    'is_public'    : ida_name.is_public_name(ea),
                    'is_autonamed' : ida_bytes.get_full_flags(ea) & ida_bytes.FF_LABL != 0
                })

        return labels

    def __process_functions(self):
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
            func_public = ida_name.is_public_name(start_ea)

            function = {
                'start_rva'    : start_ea - self._base,
                'name'         : func_name,
                'is_public'    : func_public,
                'is_autonamed' : func_autonamed
            }

            # PE32/PE32+ only support binaries up to 2GB
            if function['start_rva'] >= 2**32:
                print('RVA out of range for function: ' + function['name'], file=sys.stderr)

            self.__process_function_typeinfo(function, func)

            function['labels'] = self.__process_function_labels(func)

            functions.append(function)

            func = ida_funcs.get_next_func(start_ea)

        return functions


    def __process_names(self):
        names = list()

        for i in xrange(ida_name.get_nlist_size()):
            ea = ida_name.get_nlist_ea(i)
            if ida_funcs.get_func(ea) is not None:
                continue

            name = {
                'rva'       : ea - self._base,
                'name'      : ida_name.get_nlist_name(i),
                'is_public' : ida_name.is_public_name(ea),
                'is_func'   : ida_funcs.get_func(ea) is not None
            }

            # PE32/PE32+ only support binaries up to 2GB
            if name['rva'] >= 2**32:
                print('RVA out of range for name: ' + name['name'], file=sys.stderr)

            names.append(name)

        return names

#
# Menu handler
#

class __fakepdb_dumpinfo_actionhandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):

        filepath = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        pre, _ = os.path.splitext(filepath)
        filepath = pre + ".exe.json"

        dumper = InformationDumper()
        print('FakePDB/dumpinfo:')
        ida_auto.set_ida_state(ida_auto.st_Work)
        dumper.dump_info(filepath)
        ida_auto.set_ida_state(ida_auto.st_Ready)
        print('   * done')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    
def register_actions():
    action_desc = ida_kernwin.action_desc_t(
        'fakepdb_dumpinfo',                 # The action name. This acts like an ID and must be unique
        'Dump info to .json',               # The action text.
        __fakepdb_dumpinfo_actionhandler(), # The action handler.
        'Ctrl+Shift+1',                     # Optional: the action shortcut
        '',                                 # Optional: the action tooltip (available in menus/toolbar)
        0)                                  # Optional: the action icon (shows when in menus/toolbars)

    ida_kernwin.register_action(action_desc)
    ida_kernwin.attach_action_to_menu('Edit/FakePDB/', 'fakepdb_dumpinfo', ida_kernwin.SETMENU_APP)

