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

import ida_name
import ida_kernwin

from .signature_finder import SignatureFinder

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
