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

'''
generates PDB from the IDA database
'''

import json
import os
import subprocess
import sys
import traceback

import ida_auto
import ida_kernwin
import ida_loader

from dumpinfo import InformationDumper

class PdbGenerator:

    def __init__(self):
        self.__executable_platform = sys.platform 
        self.__executable_name = 'pdbgen.exe' if self.__executable_platform == 'win32' else 'pdbgen'
        self.__executable_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.__executable_platform, self.__executable_name)

    def generate(self, path_exe, path_json, path_pdb):
        subprocess.call([self.__executable_path, 'generate', path_exe, path_json, path_pdb])

    def get_symserv_exe(self, path_exe):
        p = subprocess.Popen([self.__executable_path, 'symserv_exe', path_exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = p.communicate()
        return stdout

    def get_symserv_pdb(self, path_exe):
        p = subprocess.Popen([self.__executable_path, 'symserv_pdb', path_exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = p.communicate()
        return stdout


#
# Menu handler
#

class __fakepdb_pdbgeneration_actionhandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        ida_auto.set_ida_state(ida_auto.st_Work)
        print('FakePDB/generate pdb:')

        dumper = InformationDumper()
        generator = PdbGenerator()

        #get exe location
        filepath_ida = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        pre, _ = os.path.splitext(filepath_ida)
        pre, _ = os.path.splitext(pre)
        filepath_exe = pre + ".exe"
        filepath_json = pre + ".exe.json"
        filepath_pdb = pre + ".pdb"

        #generate json       
        print('    * generating JSON: %s' % filepath_json)
        dumper.dump_info(filepath_json)

        print('    * generating PDB: %s' % filepath_pdb)
        generator.generate(filepath_exe, filepath_json, filepath_pdb)

        print('    * symserv EXE id: %s' % generator.get_symserv_exe(filepath_exe))
        print('    * symserv PDB id: %s' % generator.get_symserv_pdb(filepath_exe))
        print('    * done')

        ida_auto.set_ida_state(ida_auto.st_Ready)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB
    
def register_actions():
    action_desc = ida_kernwin.action_desc_t(
        'fakepdb_pdb_generation',                # The action name. This acts like an ID and must be unique
        'Generate .PDB file',                    # The action text.
        __fakepdb_pdbgeneration_actionhandler(), # The action handler.
        'Ctrl+Shift+4',                          # Optional: the action shortcut
        '',                                      # Optional: the action tooltip (available in menus/toolbar)
        0)                                       # Optional: the action icon (shows when in menus/toolbars)

    ida_kernwin.register_action(action_desc)
    ida_kernwin.attach_action_to_menu('Edit/FakePDB/', 'fakepdb_pdb_generation', ida_kernwin.SETMENU_APP)

