"""
   Copyright 2017      Maxim Smirnov
   Copyright 2017-2021 Mikhail Paulyshka

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

import ida_kernwin
import ida_nalt

from .offsets_importer import OffsetsImporter

#
# Menu handler
#

class __fakepdb_offsetsimport_actionhandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        # get active filename
        if not ida_nalt.get_root_filename():
            print('FakePDB/import offsets: file not loaded')
            return 1

        importer = OffsetsImporter()

        print('FakePDB/import offsets:')
        
        f = ida_kernwin.ask_file(False, "*.json", "Select the file to load")
        if f and os.path.exists(f):
            importer.process_json(f)
            print('    * finished')
        else:
            print('    * canceled')
                
        print('')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    
def register_actions():
    action_desc = ida_kernwin.action_desc_t(
        'fakepdb_offsets_import',                # The action name. This acts like an ID and must be unique
        'Import offsets from .json',             # The action text.
        __fakepdb_offsetsimport_actionhandler(), # The action handler.
        'Ctrl+Shift+3',                          # Optional: the action shortcut
        '',                                      # Optional: the action tooltip (available in menus/toolbar)
        0)                                       # Optional: the action icon (shows when in menus/toolbars)

    ida_kernwin.register_action(action_desc)
    ida_kernwin.attach_action_to_menu('Edit/FakePDB/', 'fakepdb_offsets_import', ida_kernwin.SETMENU_APP)
