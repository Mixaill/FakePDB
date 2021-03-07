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

__version__ = '0.3'

import ida_idaapi

import fakepdb.command_dumpinfo
import fakepdb.command_findsignature
import fakepdb.command_importoffsets
import fakepdb.command_libgenerate
import fakepdb.command_pdbgenerate


class FakePdbPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE

    comment = "FakePDB plugin"
    wanted_name = 'FakePDB'
    wanted_hotkey = ''
    help = 'https://github.com/mixaill/FakePDB'

    def init(self):
        fakepdb.command_dumpinfo.register_actions()
        fakepdb.command_findsignature.register_actions()
        fakepdb.command_importoffsets.register_actions()
        fakepdb.command_libgenerate.register_actions()
        fakepdb.command_pdbgenerate.register_actions()

        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        pass

def PLUGIN_ENTRY():
    return FakePdbPlugin()
