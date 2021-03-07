"""
   Copyright 2017      Maxim Smirnov
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


import ida_bytes
import ida_ida
import ida_idaapi
import ida_search
import ida_ua
import ida_xref

class SignatureFinder:
    def __init__(self):
        pass

    #
    # public
    #

    def get_signature(self, address_start):            
        signature_str = ''
        current_addr = address_start
        while True:
            instruction  = ida_ua.insn_t()
            instruction_len = ida_ua.decode_insn(instruction, current_addr)
            if not instruction_len:
                return ''

            signature_str += self.__add_instruction(instruction)

            rescount = self.__search_resultcount(signature_str)
            if rescount == 0:
                return ''

            if rescount == 1:
                break

            current_addr = current_addr + instruction_len

        return signature_str.strip()

    #
    # private
    #

    def __add_bytes(self, bytes_ea, bytes_count):
        sginature_str = ''
        for i in range(0, bytes_count):
            sginature_str = sginature_str + '%02X ' % ida_bytes.get_byte(bytes_ea + i)
        
        return sginature_str

    def __add_instruction(self, instruction):
        strSig = ''
        
        value_offset = self.__inst_value_offset(instruction)
        
        #in case of no instruction value, just add al the bytes
        if value_offset == 0:
            return self.__add_bytes(instruction.ea, instruction.size)
        
        #in other case, add instruction
        strSig += self.__add_bytes(instruction.ea, value_offset)

        #and then add bytes if there is no xref, or add placeholders if xrefs found
        if self.__inst_contains_xrefs(instruction):
            strSig += self.__add_placeholders(instruction.size - value_offset)
        else:
            strSig += self.__add_bytes(instruction.ea + value_offset, instruction.size - value_offset)

        return strSig

    def __add_placeholders(self, count):
        return '? ' * count

    def __search_resultcount(self, signature): 
        search_addr = ida_ida.cvar.inf.min_ea
        search_results = 0

        while search_results < 2:
            search_addr = ida_search.find_binary(search_addr, ida_ida.cvar.inf.max_ea, signature, 16, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
            if search_addr == ida_idaapi.BADADDR:
                break
            search_results += 1

        return search_results

    def __inst_contains_xrefs(self, instruction):
        if ida_xref.get_first_dref_from(instruction.ea) != ida_idaapi.BADADDR:
            return True
        if ida_xref.get_first_fcref_from(instruction.ea) != ida_idaapi.BADADDR:
            return True
        return False

    def __inst_value_offset(self, instruction):
        for i in range(0, ida_ida.UA_MAXOP):
            if instruction.ops[i].offb != 0:
                return instruction.ops[i].offb

        return 0
