"""
   Copyright 2017      Maxim Smirnov
   Copyright 2017-2020 Mikhail Paulyshka

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
imports functions by its offsets to the IDA database


required file format:
```
{
   "function_name_1": "0001:123456",
   "function_name_2": "0001:254646",
   "function_name_X": "XXXX:YYYYYY",
}
```


where:
 * XXXX: number of the PE section
 * YYYY: offset from the begining of the section in DEC
'''

import json
import os
import traceback

import ida_idaapi
import ida_kernwin
import ida_name
import ida_segment

def get_segments_map():
    segments = dict()
    for n in xrange(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)

        if seg.sel not in segments:
            segments[seg.sel] = seg.start_ea
        elif seg.start_ea < segments[seg.sel]:
             segments[seg.sel] = seg.start_ea

    return segments

def import_name(segments, name, addr):
    addr_components = addr.split(':')

    try:
        segment_ea = segments[int(addr_components[0])]
    except KeyError:
        print ('import_name: %s -> segment %s not found' % (name, addr_components[0]))
        return

    #replace <> in name because IDA does not support it
    name = name.replace('<','(').replace('>',')').encode('ascii')

    #fix situation where name already exists
    while ida_name.get_name_ea(ida_idaapi.BADADDR, name) != ida_idaapi.BADADDR:
        name = name + "_"

    ida_name.set_name(segment_ea + int(addr_components[1]), name)

def process_json(filepath):
    #get segments map
    segments = get_segments_map()

    #mark names
    offsets = None
    with open(filepath, 'r') as f:
        offsets = json.load(f)

        for key, value in offsets.iteritems():
            import_name(segments, key, value)
       
    print('Finished importing offsets')
    print('==============')

f = ida_kernwin.ask_file(False, "*.json", "Select the file to load")
if os.path.exists(f):
    process_json(f)
