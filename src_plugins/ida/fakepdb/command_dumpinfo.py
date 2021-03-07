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

import os

import ida_auto
import ida_kernwin
import ida_nalt
import ida_loader

from .dumpinfo import DumpInfo

class __fakepdb_dumpinfo_actionhandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):

        #calculate locations
        idb_dir = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
        pe_filename_ext = ida_nalt.get_root_filename()
        filepath_json = os.path.join(idb_dir, pe_filename_ext + ".json")

        dumper = DumpInfo()
        print('FakePDB/dumpinfo:')
        ida_auto.set_ida_state(ida_auto.st_Work)
        dumper.dump_info(filepath_json)
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
