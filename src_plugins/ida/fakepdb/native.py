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

import os.path
import platform
import subprocess

class Native:

    EXECUTABLE_NAME_COFF = "fakepdb_coff"
    EXECUTABLE_NAME_PDB  = "fakepdb_pdb"
    EXECUTABLE_NAME_PE   = "fakepdb_pe"

    def __init__(self):
        self.__executable_system = platform.system().lower()
        self.__executable_arch   = platform.machine().lower() 


    #
    # Commands
    #
    def coff_createlib(self, path_json, path_lib):
        return self.__run_command(Native.EXECUTABLE_NAME_COFF, ['coff_createlib', path_json, path_lib])

    def pdb_generate(self, path_json, path_pdb, path_exe, with_labels):
        cmd = ['pdb_generate']
        if with_labels:
            cmd += ['-l']
        cmd += [path_json, path_pdb, path_exe]
        return self.__run_command(Native.EXECUTABLE_NAME_PDB, cmd)

    def pe_timestamp(self, path_exe):
        return self.__run_command(Native.EXECUTABLE_NAME_PE, ['pe_timestamp', path_exe])

    def pe_guidage(self, path_exe):
        return self.__run_command(Native.EXECUTABLE_NAME_PE, ['pe_guidage', path_exe])



    #
    # Internals 
    #

    def __run_command(self, exe, args):
        p = subprocess.Popen([self.__executable_path(exe)] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = p.communicate()
        return stdout

    def __executable_path(self, name):
        if self.__executable_system == 'windows':
            name += ".exe"

        return os.path.join(os.path.dirname(os.path.realpath(__file__)), '%s_%s' % (self.__executable_system, self.__executable_arch), name)

