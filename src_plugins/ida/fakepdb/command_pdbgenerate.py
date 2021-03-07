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

class __fakepdb_pdbgeneration_actionhandler(ida_kernwin.action_handler_t):
    def __init__(self, with_labels):
        ida_kernwin.action_handler_t.__init__(self)
        self.with_labels = with_labels

    # Say hello when invoked.
    def activate(self, ctx):
        ida_auto.set_ida_state(ida_auto.st_Work)
        if self.with_labels:
            print('FakePDB/generate pdb (with function labels):')
        else:
            print('FakePDB/generate pdb:')

        dumper = DumpInfo()
        native = Native()

        #calculate locations
        idb_dir = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
        pe_filename_ext = ida_nalt.get_root_filename()
        pe_filename, _ = os.path.splitext(ida_nalt.get_root_filename())

        filepath_exe  = ida_nalt.get_input_file_path()
        filepath_json = os.path.join(idb_dir, pe_filename_ext + ".json")
        filepath_pdb  = os.path.join(idb_dir, pe_filename + ".pdb")

        #generate json       
        print('    * generating JSON: %s' % filepath_json)
        dumper.dump_info(filepath_json)

        print('    * generating PDB: %s' % filepath_pdb)
        native.pdb_generate(filepath_exe, filepath_json, filepath_pdb, self.with_labels)

        print('    * symserv EXE id: %s' % native.pe_timestamp(filepath_exe))
        print('    * symserv PDB id: %s' % native.pe_guidage(filepath_exe))
        print('    * done')

        ida_auto.set_ida_state(ida_auto.st_Ready)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    
def register_actions():
    action_desc = ida_kernwin.action_desc_t(
        'fakepdb_pdb_generation',                # The action name. This acts like an ID and must be unique
        'Generate .PDB file',                    # The action text.
        __fakepdb_pdbgeneration_actionhandler(False), # The action handler.
        'Ctrl+Shift+4',                          # Optional: the action shortcut
        '',                                      # Optional: the action tooltip (available in menus/toolbar)
        0)                                       # Optional: the action icon (shows when in menus/toolbars)

    ida_kernwin.register_action(action_desc)
    ida_kernwin.attach_action_to_menu('Edit/FakePDB/', 'fakepdb_pdb_generation', ida_kernwin.SETMENU_APP)

    action_desc = ida_kernwin.action_desc_t(
        'fakepdb_pdb_generation_labels',         # The action name. This acts like an ID and must be unique
        'Generate .PDB file (with function labels)',      # The action text.
        __fakepdb_pdbgeneration_actionhandler(True), # The action handler.
        'Ctrl+Shift+5',                          # Optional: the action shortcut
        '',                                      # Optional: the action tooltip (available in menus/toolbar)
        0)                                       # Optional: the action icon (shows when in menus/toolbars)

    ida_kernwin.register_action(action_desc)
    ida_kernwin.attach_action_to_menu('Edit/FakePDB/', 'fakepdb_pdb_generation_labels', ida_kernwin.SETMENU_APP)
