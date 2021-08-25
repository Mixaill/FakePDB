"""
   Copyright 2020-2021 Mikhail Paulyshka

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
import struct
import sys

import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_idaapi
import ida_nalt
import ida_name
import ida_netnode
import ida_segment
import ida_typeinf

#
# PE
#

class PE_Struct(object):

    def __init__(self, packinfo, data):
        (format, names) = PE_Struct.parse(packinfo)
        self.data = self.__unpack(data, format, names)

    def __unpack(self, array, format, names):
        unpack_list = {}

        unpack_tuple = struct.unpack(format, array[0:struct.calcsize(format)])
        for pair in zip(names, unpack_tuple):
            unpack_list[pair[0]] = pair[1]

        return unpack_list

    def show(self):
        for k, v in self.data.items(): 
            if isinstance(v, str):
                print("{:32} {}".format(k, v))
            else:
                print("{:32} {}".format(k, hex(v)))
        print('')

    def parse(packinfo):
        unpack_format = ''
        unpack_names = list()

        for pair in packinfo:
            unpack_format += pair[0]
            unpack_names.append(pair[1])

        return (unpack_format, unpack_names)


class PE_Header_IDA(PE_Struct):
    packinfo = [
        ['i', 'signature'],
        ['H', 'machine'],
        ['H', 'nobjs'],
        ['I', 'datetime'],
        ['I', 'symtof'],
        ['I', 'nsyms'],
        ['H', 'hdrsize'],
        ['H', 'flags'],
        ['H', 'magic'],
        ['B', 'vstamp_major'],
        ['B', 'vstamp_minor'],
        ['I', 'tsize'],
        ['I', 'dsize'],
        ['I', 'bsize'],
        ['I', 'entry'],
        ['I', 'text_start'],
        ['I', 'data_start'],
        ['I', 'imagebase32'],
        ['I', 'objalign'],
        ['I', 'filealign'],
        ['H', 'osmajor'],
        ['H', 'osminor'],
        ['H', 'imagemajor'],
        ['H', 'imageminor'],
        ['H', 'subsysmajor'],
        ['H', 'subsysminor'],
        ['I', 'reserved'],
        ['I', 'imagesize'],
        ['I', 'allhdrsize'],
        ['I', 'checksum'],
        ['H', 'subsys'],
        ['H', 'dllflags'],
        ['I', 'stackres'],
        ['I', 'stackcom'],
        ['I', 'heapres'],
        ['I', 'heapcom'],
        ['I', 'loaderflags'],
        ['I', 'nrvas'],
        ['I', 'expdir_rva'],
        ['I', 'expdir_size'],
        ['I', 'impdir_rva'],
        ['I', 'impdir_size'],
        ['I', 'resdir_rva'],
        ['I', 'resdir_size'],
        ['I', 'excdir_rva'],
        ['I', 'excdir_size'],
        ['I', 'secdir_rva'],
        ['I', 'secdir_size'],
        ['I', 'reltab_rva'],
        ['I', 'reltab_size'],
        ['I', 'debdir_rva'],
        ['I', 'debdir_size'],
        ['I', 'desstr_rva'],
        ['I', 'desstr_size'],
        ['I', 'cputab_rva'],
        ['I', 'cputab_size'],
        ['I', 'tlsdir_rva'],
        ['I', 'tlsdir_size'],
        ['I', 'loddir_rva'],
        ['I', 'loddir_size'],
        ['I', 'bimtab_rva'],
        ['I', 'bimtab_size'],
        ['I', 'iat_rva'],
        ['I', 'iat_size'],
        ['I', 'didtab_rva'],
        ['I', 'didtab_size'],
        ['I', 'comhdr_rva'],
        ['I', 'comhdr_size'],
        ['I', 'x00tab_rva'],
        ['I', 'x00tab_size'],
    ]

    def __init__(self):
        node = ida_netnode.netnode()
        node.create("$ PE header")
        
        super().__init__(PE_Header_IDA.packinfo, node.valobj())

        self.__describe_pe_signature()
        self.__describe_pe_magic()

    def get_imagebase(self):
        if self.data['signature'] == 'pe32+':
            return self.data['imagebase64']
        
        return self.data['imagebase32']

    def get_sections_debug(self):
        sec_rva = self.data['debdir_rva']
        sec_len = self.data['debdir_size']

        if sec_rva == 0 or sec_len == 0:
            return None

        sec_size = PE_Directory_Debug.get_section_size()
        sec_count = sec_len // sec_size

        result = list()
        for i in range(0, sec_count):
            result.append(PE_Directory_Debug(self.get_imagebase(), sec_rva + i*sec_size, sec_size))
        
        return result
        

    def __describe_pe_signature(self):
        val = self.data['signature']
        if val == 0x4550:
            val = 'pe'
        if val == 0x455042:
            val = 'bpe'
        if val == 0x4C50:
            val = 'pl'  
        if val == 0x4C50:
            val = 'vz'

        self.data['signature'] = val

    def __describe_pe_magic(self):
        val = self.data['magic']
        if val == 0x107:
            val = 'rom'
        if val == 0x10B:
            val = 'pe32'
        if val == '0x20B':
            val = 'pe32+'

        self.data['magic'] = val


class PE_Directory_Debug(PE_Struct):
    packinfo = [
        ['I', 'characteristics'],
        ['I', 'time_date_stamp'],
        ['H', 'major_version'],
        ['H', 'minor_version'],
        ['I', 'type'],
        ['I', 'size_of_data'],
        ['I', 'address_of_raw_data'],
        ['I', 'pointer_to_raw_data']
    ]

    def __init__(self, base, rva, size):
        self.__base = base
        super().__init__(PE_Directory_Debug.packinfo, ida_bytes.get_bytes(self.__base+rva, size))

        self.__describe_type()

    def __describe_type(self):
        val = self.data['type']

        if val == 0:
            val = 'unknown'
        elif val == 1:
            val = 'coff'
        elif val == 2:
            val = 'codeview'
        elif val == 3:
            val = 'fpo'
        elif val == 4:
            val = 'misc'
        elif val == 5:
            val = 'exception'
        elif val == 6:
            val = 'fixup'
        elif val == 7:
            val = 'omap_to_src'
        elif val == 8:
            val = 'omap_from_src'
        elif val == 9:
            val = 'borland'
        elif val == 10:
            val = 'reserved'
        elif val == 11:
            val = 'clsid'
        elif val == 12:
            val = 'vc_feature'
        elif val == 13:
            val = 'pogo'
        elif val == 14:
            val = 'iltcg'
        elif val == 15:
            val = 'mpx'
        elif val == 16:
            val = 'repro'
        elif val == 17:
            val = 'ex_dllcharacteristics'

        self.data['type'] = val

    def get_section_size():
        return struct.calcsize(PE_Struct.parse(PE_Directory_Debug.packinfo)[0])

    def get_type(self):
        return self.data['type']

    def get_codeview(self):
        if self.get_type() != 'codeview':
            return None
        
        return PE_Directory_Debug_CodeView(self.__base, self.data['address_of_raw_data'], self.data['size_of_data'])


class PE_Directory_Debug_CodeView(PE_Struct):
    packinfo = [
        ['I', 'magic'],
        ['16s', 'guid'],
        ['I', 'age'],
    ]

    def __init__(self, base, rva, size):
        self.__base = base
        super().__init__(PE_Directory_Debug_CodeView.packinfo, ida_bytes.get_bytes(self.__base + rva, size))

    def get_section_size():
        return struct.calcsize(PE_Struct.parse(PE_Directory_Debug_CodeView.packinfo)[0])



#
# DumpInfo
#

class DumpInfo():
    def __init__(self):
        pass

    #
    # public
    #

    def dump_info(self, filepath):
        self._base = ida_nalt.get_imagebase()

        output = {
            'general'   : self.__process_general(), 
            'pe'        : self.__process_pe(),
            'segments'  : self.__process_segments(),
            'exports'   : self.__process_exports(),
            'functions' : self.__process_functions(),
            'names'     : self.__process_names()
        }

        with open(filepath, "w") as f:
            json.dump(output, f, indent=4)


    #
    # private/describe
    #

    def __describe_alignment(self, align):
        #https://hex-rays.com/products/ida/support/sdkdoc/group__sa__.html
        if align == 0:
            return 1
        elif align == 1:
            return 8
        elif align == 2:
            return 16
        elif align == 3:
            return 128
        elif align == 4:
            return 2048     
        elif align == 5:
            return 32 
        elif align == 6:
            return 32768
        elif align == 7:
            return 0
        elif align == 8:
            return 256
        elif align == 9:
            return 512
        elif align == 10:
            return 64
        elif align == 11:
            return 1024
        elif align == 12:
            return 4096
        elif align == 13:
            return 8192
        elif align == 14:
            return 16384

        return 0

    def __describe_bitness(self, bitness):
        #https://hex-rays.com/products/ida/support/sdkdoc/classsegment__t.html#a7aa06d5fa4e0fc79e645d082eabf2a6a
        if bitness == 0:
            return 16
        elif bitness == 1:
            return 32
        elif bitness == 2:
            return 64

        return 0

    def __describe_permission(self, perm):
        #https://hex-rays.com/products/ida/support/sdkdoc/group___s_e_g_p_e_r_m__.html

        result = ''
        if perm & 4: 
            result += 'R'
        if perm & 2: 
            result += 'W'
        if perm & 1: 
            result += 'X'

        return result

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

    #
    # private/process
    #

    def __process_general(self):
        info_struct = ida_idaapi.get_inf_structure()

        #architecture
        arch = info_struct.procname
        if arch == 'metapc':
            arch = 'x86'
        elif arch == 'ARM':
            arch = 'arm'

        #bitness
        bitness = 16
        if info_struct.is_64bit():
            bitness = 64
        elif info_struct.is_32bit():
            bitness = 32

        result = {
            'filename'    : ida_nalt.get_root_filename(),
            'architecture': arch,
            'bitness'     : bitness
        }

        return result

    def __process_segments(self):
        segments = list()

        for n in range(0, ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if seg:
                segm = {
                    'align'     : self.__describe_alignment(seg.align),
                    'bitness'   : self.__describe_bitness(seg.bitness),
                    'name'      : ida_segment.get_segm_name(seg),
                    'rva_start' : seg.start_ea - self._base,
                    'rva_end'   : seg.end_ea - self._base,
                    'permission': self.__describe_permission(seg.perm),
                    'selector'  : seg.sel,
                    'type'      : ida_segment.get_segm_class(seg),
                }
                
                segments.append(segm)

        return segments

    def __process_function_typeinfo(self, info, func):

        tinfo = ida_typeinf.tinfo_t()
        ida_nalt.get_tinfo(tinfo,func.start_ea)
        
        func_type_data = ida_typeinf.func_type_data_t()
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

        for i in range(0, ida_name.get_nlist_size()):
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

    def __process_exports(self):
        exports = list()

        for i in range(0, ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)

            ea = ida_entry.get_entry(ordinal)

            flags = ida_bytes.get_full_flags(ea)
            type = 'unknown'
            if ida_bytes.is_func(flags):
                type = 'function'
            elif ida_bytes.is_data(flags):
                type = 'data'

            export = {
                'ordinal' : ordinal,
                'rva'     : ea - self._base,
                'name'    : ida_entry.get_entry_name(ordinal),
                'type'    : type
            }

            exports.append(export)

        return exports

    def __process_pe(self):
        result = {}

        peheader = PE_Header_IDA()

        #peheader
        result['image_datetime'] = peheader.data['datetime']
        result['image_machine'] = peheader.data['machine']
        result['image_size'] = peheader.data['imagesize']

        #debug
        pedebug = peheader.get_sections_debug()
        for sec in pedebug:
            if sec.get_type() != 'codeview':
                continue

            pe_codeview = sec.get_codeview()
            if pe_codeview is not None:
                result['pdb_age'] = pe_codeview.data['age']
                result['pdb_guid'] = list(pe_codeview.data['guid'])

        return result
