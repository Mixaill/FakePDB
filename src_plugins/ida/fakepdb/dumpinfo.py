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

import ida_pro
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
if ida_pro.IDA_SDK_VERSION < 900:
    import ida_struct


#
# PE
#


def safe_str(value, counter, default="UNKNOWN"):
    if value is None:
        return default + str(counter)
    if isinstance(value, str):
        if value.strip() == "":
            return default + str(counter)
        return value
    return str(value)


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
            'names'     : self.__process_names(),
            'types'     : self.__process_types(),
        }
        if ida_pro.IDA_SDK_VERSION < 900:
            output['structs'] = self.__process_structs()

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

    def __describe_callingconvention(self, cm_cc):
        #https://www.hex-rays.com/products/ida/support/sdkdoc/group___c_m___c_c__.html
        cc = cm_cc & ida_typeinf.CM_CC_MASK
        if cc == ida_typeinf.CM_CC_INVALID:
            return 'invalid'
        elif cc == ida_typeinf.CM_CC_UNKNOWN:
            return 'unknown'
        elif cc == ida_typeinf.CM_CC_VOIDARG:
            return 'voidarg'
        elif cc == ida_typeinf.CM_CC_CDECL:
            return 'cdecl'
        elif cc == ida_typeinf.CM_CC_ELLIPSIS:
            return 'cdecl_ellipsis'
        elif cc == ida_typeinf.CM_CC_STDCALL:
            return 'stdcall'
        elif cc == ida_typeinf.CM_CC_PASCAL:
            return 'pascal'
        elif cc == ida_typeinf.CM_CC_FASTCALL:
            return 'fastcall'
        elif cc == ida_typeinf.CM_CC_THISCALL:
            return 'thiscall'
        elif cc == ida_typeinf.CM_CC_SPOILED:
            return 'spoiled'
        elif cc == 0xB0:
            return 'reserved'
        elif cc == ida_typeinf.CM_CC_RESERVE3:
            return 'reserved'
        elif cc == ida_typeinf.CM_CC_SPECIALE:
            return 'special_ellipsis'
        elif cc == ida_typeinf.CM_CC_SPECIALP:
            return 'special_pstack'
        elif cc == ida_typeinf.CM_CC_SPECIAL:
            return 'special'

        if ida_pro.IDA_SDK_VERSION < 900:
            if cc == ida_typeinf.CM_CC_MANUAL:
                return 'manual'

        return 'unknown_%s' % cc

    def __describe_memorymodel_code(self, cm_cc):
        #https://hex-rays.com/products/ida/support/sdkdoc/group___c_m___m__.html
        cm = cm_cc & ida_typeinf.CM_M_MASK
        
        if cm == ida_typeinf.CM_M_NN:
            return 'near'
        elif cm == ida_typeinf.CM_M_FF:
            return 'far'
        elif cm == ida_typeinf.CM_M_NF:
            return 'near'
        elif cm == ida_typeinf.CM_M_FN:
            return 'far'
        
        return 'unknown_%s' % cm_cc

    def __describe_memorymodel_data(self, cm_cc):
        #https://hex-rays.com/products/ida/support/sdkdoc/group___c_m___m__.html
        cm = cm_cc & ida_typeinf.CM_M_MASK
        
        if cm == ida_typeinf.CM_M_NN:
            return 'near'
        elif cm == ida_typeinf.CM_M_FF:
            return 'far'
        elif cm == ida_typeinf.CM_M_NF:
            return 'far'
        elif cm == ida_typeinf.CM_M_FN:
            return 'near'
        
        return 'unknown_%s' % cm_cc

    def __describe_struct_type(self, st_props):
        #https://hex-rays.com/products/ida/support/sdkdoc/group___s_f__.html

        result = ''

        if st_props & ida_struct.SF_GHOST != 0:
            result += 'ghost_'

        if st_props & ida_struct.SF_VAR != 0:
            result += 'variable_'

        if st_props & ida_struct.SF_FRAME != 0:
            result += 'frame'
        elif st_props & ida_struct.SF_UNION != 0:
            result += 'union'
        else:
            result += 'struct'

        return result

    def __describe_type_basetype(self, type):
        #https://hex-rays.com/products/ida/support/sdkdoc/group__tf.html

        type_base = type & ida_typeinf.TYPE_BASE_MASK
        type_flags = type & ida_typeinf.TYPE_FLAGS_MASK
        type_modif = type & ida_typeinf.TYPE_MODIF_MASK

        if type_base == ida_typeinf.BT_UNK:
            if type_flags == ida_typeinf.BTMT_SIZE12:
                return 'void_16'
            if type_flags == ida_typeinf.BTMT_SIZE48:
                return 'void_64'   
            if type_flags == ida_typeinf.BTMT_SIZE128:
                return 'void_unknown'   
              
            return 'void'
        
        elif type_base == ida_typeinf.BT_VOID:
            if type_flags == ida_typeinf.BTMT_SIZE12:
                return 'void_8'
            if type_flags == ida_typeinf.BTMT_SIZE48:
                return 'void_32'   
            if type_flags == ida_typeinf.BTMT_SIZE128:
                return 'void_128'   
            
            return 'void'

        elif type_base == ida_typeinf.BT_INT8:
            if type_flags == ida_typeinf.BTMT_CHAR:
                return 'char'
            elif type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_8'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_8'
            
            return 'int_8'

        elif type_base == ida_typeinf.BT_INT16:
            if type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_16'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_16'
            
            return 'int_16'

        elif type_base == ida_typeinf.BT_INT32:
            if type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_32'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_32'
            
            return 'int_32'

        elif type_base == ida_typeinf.BT_INT64:
            if type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_64'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_64'
            
            return 'int_64'

        elif type_base == ida_typeinf.BT_INT128:
            if type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_128'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_128'
            
            return 'int_128'

        elif type_base == ida_typeinf.BT_INT:
            if type_flags == ida_typeinf.BTMT_CHAR:
                return 'seg_register'
            elif type_flags == ida_typeinf.BTMT_UNSIGNED:
                return 'uint_native'
            elif type_flags == ida_typeinf.BTMT_SIGNED:
                return 'sint_native'
            
            return 'int_native'

        elif type_base == ida_typeinf.BT_BOOL:
            if type_flags == ida_typeinf.BTMT_BOOL1:
                return 'bool_8'
            elif type_flags == ida_typeinf.BTMT_BOOL2:
                return 'bool_16'
            elif type_flags == ida_typeinf.BTMT_BOOL4:
                return 'bool_32'
            elif type_flags == ida_typeinf.BTMT_BOOL8:
                return 'bool_64'

            return 'bool'

        elif type_base == ida_typeinf.BT_FLOAT:
            if type_flags == ida_typeinf.BTMT_FLOAT:
                return 'float_32'
            elif type_flags == ida_typeinf.BTMT_DOUBLE:
                return 'float_64'
            elif type_flags == ida_typeinf.BTMT_LNGDBL:
                return 'float_longdbl'
            elif type_flags == ida_typeinf.BTMT_SPECFLT:
                return 'float_varsize'

            return 'float'

        if type_base == ida_typeinf.BT_PTR:
            if type_flags == ida_typeinf.BTMT_NEAR:
                return 'ptr_near'
            elif type_flags == ida_typeinf.BTMT_FAR:
                return 'ptr_far'
            elif type_flags == ida_typeinf.BTMT_CLOSURE:
                return 'ptr_closure'

            return 'ptr'

        if type_base == ida_typeinf.BT_ARRAY:
            if type_flags == ida_typeinf.BTMT_NONBASED:
                return 'array_nonbased'
            elif type_flags == ida_typeinf.BTMT_ARRESERV:
                return 'array_reserved'

            return 'array'


        if type_base == ida_typeinf.BT_FUNC:
            if type_flags == ida_typeinf.BTMT_NEARCALL:
                return 'func_near'
            elif type_flags == ida_typeinf.BTMT_FARCALL:
                return 'func_far'
            elif type_flags == ida_typeinf.BTMT_INTCALL:
                return 'func_int'

            return 'func'

        if type_base == ida_typeinf.BT_COMPLEX:
            if type_flags == ida_typeinf.BTMT_STRUCT:
                return 'struct'
            elif type_flags == ida_typeinf.BTMT_UNION:
                return 'union'
            elif type_flags == ida_typeinf.BTMT_ENUM:
                return 'enum'
            elif type_flags == ida_typeinf.BTMT_TYPEDEF:
                return 'typedef'

            return 'complex'    

        if type_base == ida_typeinf.BT_BITFIELD:
            if type_flags == ida_typeinf.BTMT_BFLDI8:
                return 'bitfield_8'
            elif type_flags == ida_typeinf.BTMT_BFLDI16:
                return 'bitfield_16'
            elif type_flags == ida_typeinf.BTMT_BFLDI32:
                return 'bitfield_32'
            elif type_flags == ida_typeinf.BTMT_BFLDI64:
                return 'bitfield_64'

            return 'bitfield'    

        return 'unknown_%s_%s_%s' % (hex(type_base), hex(type_flags), hex(type_modif))

    #
    # private/get
    #

    def __get_type_data(self, ea):
        tinfo = ida_typeinf.tinfo_t()
        ida_nalt.get_tinfo(tinfo, ea)
        func_type_data = ida_typeinf.func_type_data_t()
        tinfo.get_func_details(func_type_data)
        
        return func_type_data


    #
    # private/process
    #

    def __process_general(self):
        info_struct = None
        if ida_pro.IDA_SDK_VERSION < 900:
            info_struct = ida_idaapi.get_inf_structure()

        #architecture
        arch = None
        if ida_pro.IDA_SDK_VERSION >= 900:
            arch = ida_ida.inf_get_procname()
        else:
            arch = info_struct.procname

        if arch == 'metapc':
            arch = 'x86'
        elif arch == 'ARM':
            arch = 'arm'

        #bitness
        bitness = 0
        if ida_pro.IDA_SDK_VERSION >= 900:
            if ida_ida.inf_is_64bit():
                bitness = 64
            elif ida_ida.inf_is_16bit():
                bitness = 16
            else:
                bitness = 32
        else:
            if info_struct.is_64bit():
                bitness = 64
            elif info_struct.is_32bit():
                bitness = 32
            else:
                bitness = 16

        result = {
            'filename'    : ida_nalt.get_root_filename(),
            'architecture': arch,
            'bitness'     : bitness
        }

        return result

    def __process_segments(self):
        segments = list()

        unkIdx = 0
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



                problem = False

                segm['name'] = safe_str(segm.get('name'), unkIdx)
                if segm['name'].startswith("UNKNOWN"):
                    problem = True
                    print('Encountered a nameless segment:')
                    print(f"    location: {seg.start_ea:X} => try analyzing this address")
                    print("    Segment name changed to: " + segm['name'] + '\n')

                segm['permission'] = safe_str(segm.get('permission'), unkIdx)
                if segm['permission'].startswith("UNKNOWN"):
                    problem = True
                    print('Encountered a segment permission problem:')
                    print(f"    name: {segm['name']}  location: {seg.start_ea:X} => try analyzing")
                    print("    Segment permission changed to: " + segm['permission'] + '\n')

                segm['type'] = safe_str(segm.get('type'), unkIdx)
                if segm['type'].startswith("UNKNOWN"):
                    problem = True
                    print('Encountered a segment type problem:')
                    print(f"    name: {segm['name']}  location: {seg.start_ea:X} => try analyzing")
                    print("    Segment type changed to: " + segm['type'] + '\n')

                if problem:
                    unkIdx = unkIdx + 1

                segments.append(segm)

        return segments

    def __process_function_typeinfo(self, info, func):

        func_type_data = self.__get_type_data(func.start_ea)

        #calling convention
        info['calling_convention'] = self.__describe_callingconvention(func_type_data.cc)
        info['memory_model_code']  = self.__describe_memorymodel_code(func_type_data.cc)
        info['memory_model_data']  = self.__describe_memorymodel_data(func_type_data.cc)

        #return type
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

        # find EA
        start = 0
        end = 0
        if ida_pro.IDA_SDK_VERSION >= 900:
            start = ida_ida.inf_get_min_ea()
            end = ida_ida.inf_get_max_ea()
        else:
            start = ida_ida.cvar.inf.min_ea
            end   = ida_ida.cvar.inf.max_ea

        # find first function head chunk in the range
        chunk = ida_funcs.get_fchunk(start)
        
        if not chunk:
            chunk = ida_funcs.get_next_fchunk(start)
        while chunk and chunk.start_ea < end and (chunk.flags & ida_funcs.FUNC_TAIL) != 0:
            chunk = ida_funcs.get_next_fchunk(chunk.start_ea)
        
        func = chunk

        unkIdx = 0
        while func and func.start_ea < end:
            start_ea = func.start_ea
            
            func_flags = ida_bytes.get_full_flags(start_ea)
            func_name = ida_funcs.get_func_name(start_ea)
            func_name_demangled = ida_name.get_demangled_name(start_ea, 0xFFFF, 0, 0)
            func_autonamed = func_flags & ida_bytes.FF_LABL != 0
            func_public = ida_name.is_public_name(start_ea)

            function = {
                'start_rva'     : start_ea - self._base,
                'name'          : func_name,
                'name_demangled': func_name_demangled,
                'is_public'     : func_public,
                'is_autonamed'  : func_autonamed
            }

            function['name'] = safe_str(function.get('name'), unkIdx )
            if function['name'].startswith("UNKNOWN"):
                unkIdx = unkIdx + 1
                print('Encountered a nameless function:')
                print(f"    location: {start_ea:X} => try analyzing this address")
                print("    Function name changed to: " + function['name'] + '\n')

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

        unkIdx = 0
        for i in range(0, ida_name.get_nlist_size()):
            ea = ida_name.get_nlist_ea(i)
            if ida_funcs.get_func(ea) is not None:
                continue

            if ida_name.get_nlist_name(i) is None:
                continue

            name = {
                'rva'            : ea - self._base,
                'name'           : ida_name.get_nlist_name(i),
                'name_demangled' : ida_name.get_demangled_name(ea, 0xFFFF, 0, 0),
                'is_public'      : ida_name.is_public_name(ea),
                'is_func'        : ida_funcs.get_func(ea) is not None
            }

            name['name'] = safe_str(name.get('name'), unkIdx)
            if name['name'] == "UNKNOWN":
                unkIdx = unkIdx + 1
                print('Encountered a null Name:')
                print(f"    location: {ea:X} => try analyzing this address")
                print("    Name changed to: " + name['name'] + '\n')

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
            type_data = self.__get_type_data(ea)
            type = 'unknown'
            if ida_bytes.is_func(flags):
                type = 'function'
            elif ida_bytes.is_data(flags):
                type = 'data'

            export = {
                'ordinal'           : ordinal,
                'rva'               : ea - self._base,
                'name'              : ida_entry.get_entry_name(ordinal),
                'type'              : type,
                'calling_convention': self.__describe_callingconvention(type_data.cc)
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
        result['image_base'] = peheader.get_imagebase()

        #debug
        result['pdb_age'] = 0
        result['pdb_guid'] = [0] * 16

        peheader_debug = peheader.get_sections_debug()
        if peheader_debug is not None:
            for section in peheader_debug:
                if section.get_type() != 'codeview':
                    continue

                pe_codeview = section.get_codeview()
                if pe_codeview is not None:
                    result['pdb_age'] = pe_codeview.data['age']
                    result['pdb_guid'] = list(pe_codeview.data['guid'])

        return result

    def __process_struct_members(self, st_obj):
        
        members = []
        for st_member in st_obj.members:
            mem_name = ida_struct.get_member_name(st_member.id) or ('unknown_%s' % st_member.id)
            
            mem_off_start = 0 if st_obj.is_union() else st_member.soff
            mem_off_end   = st_member.eoff

            mem_tinfo = ida_typeinf.tinfo_t()
            ida_struct.get_member_tinfo(mem_tinfo, st_member)
            
            mem_typename = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, mem_tinfo, '', '')
            if not mem_typename:
                mem_typename = self.__describe_type_basetype(mem_tinfo.get_realtype())

            members.append({
                'offset' : mem_off_start,
                'length' : mem_off_end - mem_off_start,
                'type'   : mem_typename,
                'name'   : mem_name,
            })
        
        return members

    def __process_structs(self):
        structs = []

        st_idx  = ida_struct.get_first_struc_idx()
        while st_idx != ida_idaapi.BADADDR:

            st_id = ida_struct.get_struc_by_idx(st_idx)
            st_obj = ida_struct.get_struc(st_id)

            st_name = ida_struct.get_struc_name(st_id)
                    
            structs.append({
                'type'            : self.__describe_struct_type(st_obj.props),
                'name'            : st_name,
                'size'            : int(ida_struct.get_struc_size(st_obj)), 
                'members'         : self.__process_struct_members(st_obj)
            })

            st_idx = ida_struct.get_next_struc_idx(st_idx)
           
        return structs

    def __process_types_enum_member(self, enum_member : ida_typeinf.enum_member_t):
        result = {}
        
        result['name'] = enum_member.name
        result['value'] = enum_member.value

        return result

    def __process_types_udt_member(self, udt_member : ida_typeinf.udt_member_t):
        result = {}
        
        result['name'] = udt_member.name
        result['offset'] = udt_member.offset // 8
        result['size'] = udt_member.size // 8

        udt_mem_type = udt_member.type
        udt_mem_typename = udt_member.type.get_type_name()
        if not udt_mem_typename:
            udt_mem_typename = self.__describe_type_basetype(udt_mem_type.get_realtype())
        result['type'] = udt_mem_typename

        return result

    def __process_types_tinfo(self, ti_info : ida_typeinf.tinfo_t):
        localtype = {}
        
        localtype['name'] = ti_info.get_type_name()
        localtype['basetype'] = self.__describe_type_basetype(ti_info.get_realtype())
        localtype['size'] = ti_info.get_size()
        if localtype['size'] == ida_idaapi.BADADDR:
            localtype['size'] = 0

        ti_udt = ida_typeinf.udt_type_data_t()
        ti_enum = ida_typeinf.enum_type_data_t()

        if ti_info.get_udt_details(ti_udt):
            members = []
            for member in ti_udt:
                members.append(self.__process_types_udt_member(member))

            localtype['members'] = members
        elif ti_info.get_enum_details(ti_enum):
            members = []
            for member in ti_enum:
                members.append(self.__process_types_enum_member(member))

            localtype['members'] = members

        return localtype

    def __process_types(self):
        localtypes = []

        ti_lib_obj = ida_typeinf.get_idati()

        ti_lib_count = 0
        if ida_pro.IDA_SDK_VERSION >= 900:
            ida_typeinf.get_ordinal_count(ti_lib_obj)
        else:
            ti_lib_count = ida_typeinf.get_ordinal_qty(ti_lib_obj)

        for ti_ordinal in range(1, ti_lib_count + 1):
            ti_info = ida_typeinf.tinfo_t()
            if ti_info.get_numbered_type(ti_lib_obj, ti_ordinal):
                localtypes.append(self.__process_types_tinfo(ti_info))

        return localtypes
