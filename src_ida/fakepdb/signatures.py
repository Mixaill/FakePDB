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

import ida_bytes
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_name
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
        for i in xrange(bytes_count):
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
        for i in xrange(ida_ida.UA_MAXOP):
            if instruction.Operands[i].offb != 0:
                return instruction.Operands[i].offb

        return 0

#
# Menu handler
#

class __fakepdb_findsig_actionhandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):

        screen_ea = ida_kernwin.get_screen_ea()

        finder = SignatureFinder()
        sig = finder.get_signature(screen_ea)
        print('FakePDB/signatures_find:')
        print('   * address  : %s' % hex(screen_ea))
        print('   * name     : %s' % ida_name.get_name(screen_ea))
        print('   * signature: %s' % sig)
        print('')
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    
def register_actions():
    action_desc = ida_kernwin.action_desc_t(
        'fakepdb_signatures_find',         # The action name. This acts like an ID and must be unique
        'Find signature',                  # The action text.
        __fakepdb_findsig_actionhandler(), # The action handler.
        'Ctrl+Shift+2',                    # Optional: the action shortcut
        '',                                # Optional: the action tooltip (available in menus/toolbar)
        0)                                 # Optional: the action icon (shows when in menus/toolbars)

    ida_kernwin.register_action(action_desc)
    ida_kernwin.attach_action_to_menu('Edit/FakePDB/', 'fakepdb_signatures_find', ida_kernwin.SETMENU_APP)
