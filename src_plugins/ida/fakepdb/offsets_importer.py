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

import json

import ida_idaapi
import ida_name
import ida_segment

class OffsetsImporter:
    '''
    imports functions by its offsets to the IDA database


    required file format:
    ```
    {
    "function_name_1": "0001:123456",
    "function_name_2": "0001:254646",
    "function_name_X": "XXXX:YYYYYY",
    "function_name_Y": "0x0124567AF",
    }
    ```


    where:
    * XXXX: number of the PE section
    * YYYY: offset from the begining of the section in DEC
    * 0x0124567AF: IDA effective address
    '''

    def __init__(self):
        pass

    #
    # public
    #

    def process_json(self, filepath):
        #get segments map
        segments = self.__get_segments_map()

        #mark names
        offsets = None
        with open(filepath, 'r') as f:
            offsets = json.load(f)

            for key, value in offsets.iteritems():
                self.__import_name(segments, key, value)

    #
    # private
    #

    def __get_segments_map(self):
        segments = dict()
        for n in range(0, ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)

            if seg.sel not in segments:
                segments[seg.sel] = seg.start_ea
            elif seg.start_ea < segments[seg.sel]:
                segments[seg.sel] = seg.start_ea

        return segments

    def __import_name(self, segments, name, addr):
        addr_components = addr.split(':')

        name_addr = 0
        if len(addr_components) > 1:
            try:
                segment_ea = segments[int(addr_components[0])]
                name_addr = segment_ea + int(addr_components[1])
            except KeyError:
                print ('import_name: %s -> segment %s not found' % (name, addr_components[0]))
                return
        else:
            name_addr = int(addr_components[0], 16)

        #replace <> in name because IDA does not support it
        name = name.replace('<','(').replace('>',')').encode('ascii')

        #fix situation where name already exists
        while ida_name.get_name_ea(ida_idaapi.BADADDR, name) != ida_idaapi.BADADDR:
            name = name + "_"

        ida_name.set_name(name_addr, name)
