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
import sys
import subprocess

class Native:

    EXECUTABLE_NAME_WIN = "fakepdb.exe"
    EXECUTABLE_NAME_LIN = "fakepdb"

    def __init__(self):
        self.__executable_name = ''
        self.__executable_platform = sys.platform

        if self.__executable_platform == 'win32':
            self.__executable_name = Native.EXECUTABLE_NAME_WIN
        else:
            self.__executable_name = Native.EXECUTABLE_NAME_LIN

        self.__executable_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.__executable_platform, self.__executable_name)


    def coff_createlib(self, path_json, path_lib):
        return self.__run_command(['coff_createlib', path_json, path_lib])


    def pdb_generate(self, path_exe, path_json, path_pdb, with_labels):
        cmd = ['pdb_generate']
        if with_labels:
            cmd += ['-l']
        cmd += [path_exe, path_json, path_pdb]
        return self.__run_command(cmd)

    def pe_timestamp(self, path_exe):
        return self.__run_command(['pe_timestamp', path_exe])

    def pe_guidage(self, path_exe):
        return self.__run_command(['pe_guidage', path_exe])

    def __run_command(self, args):
        p = subprocess.Popen([self.__executable_path] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = p.communicate()
        return stdout
