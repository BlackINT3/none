/**
 *
 * WOW64Ext Library
 *
 * Copyright (c) 2014 ReWolf
 * http://blog.rewolf.pl/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#pragma once

extern HANDLE g_heap;
extern BOOL g_isWow64;

void* wow64ext_malloc(size_t size)
{
	return HeapAlloc(g_heap, 0, size);
}

void wow64ext_free(void* ptr)
{
	if (nullptr != ptr)
		HeapFree(g_heap, 0, ptr);
}

class CMemPtr
{
private:
    void** m_ptr;
    bool watchActive;

public:
    CMemPtr(void** ptr) : m_ptr(ptr), watchActive(true) {}

    ~CMemPtr()
    {
        if (*m_ptr && watchActive)
        { 
            wow64ext_free(*m_ptr); 
            *m_ptr = 0; 
        } 
    }

    void disableWatch() { watchActive = false; }
};

#define WATCH(ptr) \
    CMemPtr watch_##ptr((void**)&ptr)

#define DISABLE_WATCH(ptr) \
    watch_##ptr.disableWatch()
