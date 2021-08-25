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

'''
generates PDB from the IDA database
'''

import os

import ida_auto
import ida_kernwin
import ida_loader
import ida_nalt

from .dumpinfo import DumpInfo
from .native import Native

#
# Menu handler
#

class __fakepdb_libgeneration_actionhandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        # get active filename
        pe_filename_ext = ida_nalt.get_root_filename()
        if not pe_filename_ext:
            print('FakePDB/generate lib: file not loaded')
            return 1

        ida_auto.set_ida_state(ida_auto.st_Work)
        print('FakePDB/generate lib:')

        dumper = DumpInfo()
        native = Native()

        #calculate locations
        idb_dir = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
        
        pe_filename, _ = os.path.splitext(ida_nalt.get_root_filename())

        filepath_exe  = ida_nalt.get_input_file_path()
        filepath_json = os.path.join(idb_dir, pe_filename_ext + ".json")
        filepath_lib  = os.path.join(idb_dir, pe_filename + ".lib")

        #generate json       
        print('    * generating JSON: %s' % filepath_json)
        dumper.dump_info(filepath_json)

        print('    * generating LIB: %s' % filepath_lib)
        native.coff_createlib(filepath_json, filepath_lib)

        print('    * done')

        ida_auto.set_ida_state(ida_auto.st_Ready)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    
def register_actions():
    action_desc = ida_kernwin.action_desc_t(
        'fakepdb_lib_generation',         # The action name. This acts like an ID and must be unique
        'Generate .LIB file (with function labels)', # The action text.
        __fakepdb_libgeneration_actionhandler(), # The action handler.
        'Ctrl+Shift+6',                          # Optional: the action shortcut
        '',                                      # Optional: the action tooltip (available in menus/toolbar)
        0)                                       # Optional: the action icon (shows when in menus/toolbars)

    ida_kernwin.register_action(action_desc)
    ida_kernwin.attach_action_to_menu('Edit/FakePDB/', 'fakepdb_lib_generation', ida_kernwin.SETMENU_APP)
