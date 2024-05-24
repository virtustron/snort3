//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// #include "detection/extract.h"
// #include "framework/cursor.h"
// #include "framework/endianness.h"
// #include "framework/ips_info.h"
// #include "framework/ips_option.h"
// #include "framework/module.h"
// #include "hash/hash_key_operations.h"
// #include "log/messages.h"
// #include "profiler/profiler.h"
// #include "protocols/packet.h"
// #include "utils/util.h"

#include "extract.h"

using namespace snort;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    /*
    SO_PUBLIC int byte_extract(
        int endianness, 
        int bytes_to_grab, 
        const uint8_t* ptr,
        const uint8_t* start, 
        const uint8_t* end, 
        uint32_t* value);
    */

    // Ensure there is enough data 
    if (size < sizeof(int) * 2 + sizeof(uint32_t)) 
    {
        return 0; 
    }

    int endianness = data[0]; 
    int bytes_to_grab = data[1]; 

    // Make sure we have enough data for 'bytes_to_grab'.
    if (size < sizeof(int) * 2 + bytes_to_grab + sizeof(uint32_t)) 
    {
        return 0; 
    }

    // Set up 'ptr', 'start', and 'end'.
    const uint8_t* ptr = &data[sizeof(int) * 2]; // Data starts after the two ints.
    const uint8_t* start = ptr;                  // Assuming 'start' points to the beginning of 'ptr'.
    const uint8_t* end = start + bytes_to_grab;  // End after 'bytes_to_grab' bytes.

    // Ensure 'end' does not exceed the buffer limit.
    if (end > data + size) 
    {
        return 0;               // 'end' is out of bounds.
    }

    uint32_t value = 0; // Will be filled by byte_extract.

    // Call the byte_extract function.
    int result = byte_extract(endianness, bytes_to_grab, ptr, start, end, &value);

    return 0;
}