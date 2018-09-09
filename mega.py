import os
import collections
import argparse
import ctypes
from os.path import abspath, join, dirname
import re
import logging

try:
    import capstone
except ImportError:
    print 'install capstone python binarys'
    exit(1)

try:
    from pefile import PE
except ImportError as e:
    print 'install pefile'
    exit(2)


ARCH = ctypes.sizeof(ctypes.c_voidp)*8
DEFAULT_SRV = "srv*https://msdl.microsoft.com/download/symbols"
SYMBOL_SERVER_ENV_VAR = "_NT_SYMBOL_PATH"
MAX_PATH = 260

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664
SSRVOPT_GUIDPTR = 0x00000008


class SymOpts(object):
    SYMOPT_EXACT_SYMBOLS = 0x00000400
    SYMOPT_DEBUG = 0x80000000
    SYMOPT_UNDNAME = 0x00000002


class GUID(ctypes.Structure):
    _fields_ = [
        ('Data1', ctypes.c_long),
        ('Data2', ctypes.c_short),
        ('Data3', ctypes.c_short),
        ('Data4', ctypes.c_char*8),
    ]


class SYMSRV_INDEX_INFO(ctypes.Structure):
    _fields_ = [
        ('sizeofstruct', ctypes.c_uint),
        ('file', ctypes.c_char*(MAX_PATH+1)),
        ('stripped', ctypes.c_uint),
        ('timestamp', ctypes.c_uint),
        ('size', ctypes.c_uint),
        ('dbgfile', ctypes.c_char*(MAX_PATH+1)),
        ('pdbfile', ctypes.c_char*(MAX_PATH+1)),
        ('guid', GUID),
        ('sig', ctypes.c_uint),
        ('age', ctypes.c_uint)
    ]


class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ('SizeOfStruct', ctypes.c_uint),
        ('TypeIndex', ctypes.c_uint),
        ('Reserved', ctypes.c_ulonglong*2),
        ('Index', ctypes.c_uint),
        ('Size', ctypes.c_uint),
        ('ModBase', ctypes.c_ulonglong),
        ('Flags', ctypes.c_uint),
        ('Value', ctypes.c_ulonglong),
        ('Address', ctypes.c_ulonglong),
        ('Register', ctypes.c_uint),
        ('Scope', ctypes.c_uint),
        ('Tag', ctypes.c_uint),
        ('NameLen', ctypes.c_uint),
        ('MaxNameLen', ctypes.c_uint),
        ('Name', ctypes.c_char*1)
    ]


class PeInfo(object):
    def __init__(self, filepath, pdbpath, symbols=None):
        self.filepath = filepath
        self.pdbpath = pdbpath
        self.symbols = symbols or []


class SymSession(object):
    ctypes.windll.kernel32.LoadLibraryA(
        join(dirname(abspath(__file__)), '%d' % ARCH, 'dbghelp.dll'))
    ctypes.windll.kernel32.LoadLibraryA('symsrv')
    dbghelp = ctypes.windll.dbghelp
    sid = 1

    def __init__(self, server=None, debug=False, opts=SymOpts.SYMOPT_EXACT_SYMBOLS):
        self.h = SymSession.sid
        SymSession.sid += 1

        self.bases = {}
        self.session = None
        self.debug = debug
        self.opts = opts

        if self.debug:
            self.opts |= SymOpts.SYMOPT_DEBUG

        self.srv = server
        if self.srv is None:
            self.srv = os.getenv(SYMBOL_SERVER_ENV_VAR, DEFAULT_SRV)

    def init(self):
        self.dbghelp.SymInitialize(self.h, None, 0)
        self.dbghelp.SymSetOptions(self.opts)
        if self.srv:
            self.dbghelp.SymSetSearchPath(self.h, self.srv)

    def cleanup(self):
        unl = self.dbghelp.SymUnloadModule64
        unl.argtypes = [ctypes.c_uint, ctypes.c_ulonglong]
        for baseofdll in self.bases:
            self.dbghelp.SymUnloadModule64(self.h, baseofdll)

        self.dbghelp.SymCleanup(self.h)

    def load(self, filepath, machine, sizeofImage, imageBase):
        # no need to worry about wow redirection because we must match file arch
        if machine != {32: IMAGE_FILE_MACHINE_I386, 64:
                       IMAGE_FILE_MACHINE_AMD64}[ARCH]:
            raise Exception('Architecture mismatch. Python: x{}; file: x{}'.format(
                ARCH, {64: 86, 32: 64}[ARCH]))

        idxinfo = SYMSRV_INDEX_INFO(ctypes.sizeof(SYMSRV_INDEX_INFO))
        _f = self.dbghelp.SymSrvGetFileIndexInfo
        _f.restype = ctypes.c_uint
        _f.argtypes = [ctypes.c_char_p, ctypes.POINTER(
            SYMSRV_INDEX_INFO), ctypes.c_uint]

        if not _f(filepath, ctypes.byref(idxinfo), 0):
            raise Exception(
                'failed SymSrvGetFileIndexInfo last error:  %d' % ctypes.GetLastError())

        _f = self.dbghelp.SymFindFileInPath
        _f.restype = ctypes.c_uint

        pdbpath = ctypes.create_string_buffer(MAX_PATH + 1)
        _f.argtypes = [ctypes.c_uint,
                       ctypes.c_uint,
                       ctypes.c_char_p,
                       ctypes.POINTER(GUID),
                       ctypes.c_uint,
                       ctypes.c_uint,
                       ctypes.c_uint,
                       ctypes.c_char_p,
                       ctypes.c_uint,
                       ctypes.c_uint
                       ]

        if not _f(self.h,
                  0,
                  ctypes.c_char_p(idxinfo.pdbfile),
                  ctypes.byref(idxinfo.guid),
                  idxinfo.age,
                  0,
                  SSRVOPT_GUIDPTR,
                  pdbpath,
                  0,
                  0
                  ):
            raise Exception(
                'failed SymFindFileInPath last error:  %d' % ctypes.GetLastError())

        _f = self.dbghelp.SymLoadModuleEx
        _f.restype = ctypes.c_size_t
        _f.argtypes = [ctypes.c_uint,
                       ctypes.c_uint,
                       ctypes.c_char_p,
                       ctypes.c_uint,
                       ctypes.c_ulonglong,
                       ctypes.c_uint,
                       ctypes.c_uint,
                       ctypes.c_uint
                       ]

        dllbase = _f(self.h,
                     0,
                     ctypes.c_char_p(filepath),
                     0,
                     imageBase,
                     sizeofImage,
                     0,
                     0
                     )
        if not dllbase:
            raise Exception(
                'failed SymLoadModuleEx last error:  %d' % ctypes.GetLastError())

        if dllbase in self.bases:
            raise Exception(
                '{} already in bases: {}'.format(dllbase, self.bases))

        self.bases[dllbase] = PeInfo(filepath, pdbpath)

        return dllbase

    def _fix_syminfo(self, syminfo):
        Sym = collections.namedtuple('Symbol', ['Name', 'NameLen', 'MaxNameLen', 'Tag', 'Scope',
                                                'Register', 'Address', 'Value', 'Flags', 'ModBase', 'Size', 'Index', 'TypeIndex'])
        return Sym(ctypes.string_at(ctypes.addressof(syminfo)+SYMBOL_INFO.Name.offset), syminfo.NameLen, syminfo.MaxNameLen, syminfo.Tag, syminfo.Scope, syminfo.Register, syminfo.Address, syminfo.Value, syminfo.Flags, syminfo.ModBase, syminfo.Size, syminfo.Index, syminfo.TypeIndex)

    def _enum_symbol_callback(self, syminfo, symsize, dllbase):

        fixed = self._fix_syminfo(syminfo)

        self.bases[dllbase].symbols.append(fixed)

    def _get_callback(self, dllbase):
        CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(
            SYMBOL_INFO), ctypes.c_ulong, ctypes.c_void_p)

        def callbackwrapper(syminfo, symsize, opq):
            self._enum_symbol_callback(syminfo.contents, symsize, dllbase)
        return CALLBACK(callbackwrapper)

    def _load_symbols(self, dllbase, mask):
        _f = self.dbghelp.SymEnumSymbols
        _f.restype = ctypes.c_uint
        _f.argtypes = [
            ctypes.c_uint,
            ctypes.c_ulonglong,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]

        _f(self.h, dllbase, mask, self._get_callback(dllbase), None)

    def find(self, dllbase, target=None, mask='*'):
        """
        dllbase: returned from load function
        targets: regex rule  to match symobl
        mask:    internal mask to pass to SymEnumSymbols (windbg format), will only be used the first time symbols are loaded
        """
        if dllbase not in self.bases:
            raise Exception(
                'given base: {} does not exist in {}'.format(dllbase, self.bases))

        if not self.bases[dllbase].symbols:
            self._load_symbols(dllbase, mask)

        if target is None:
            return self.bases[dllbase].symbols

        t = re.compile(target)
        res = []
        for sym in self.bases[dllbase].symbols:
            if t.match(sym.Name):
                res.append(sym)
        return res


def patch(f, outfile, nav, stomp, stomp_is_isdirty):

    nav_start = nav.Address - nav.ModBase
    target_call_address = stomp.Address - stomp.ModBase
    # physaddr = f.get_physical_by_rva(nav_start)

    md = capstone.Cs(capstone.CS_ARCH_X86, {
                     64: capstone.CS_MODE_64, 32: capstone.CS_MODE_32}[ARCH])
    md.detail = True
    code = f.get_data(nav_start, 0x300)  # should be more than enough
    possible_addresses = []

    for i in md.disasm(code, nav_start):
        # print "{:X}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str)

        if i.mnemonic.lower() == 'call' and len(i.operands) == 1:
            if target_call_address == i.operands[0].imm:
                # print 'found it?', hex(i.address+ i.size)
                possible_addresses.append(i.address + i.size-nav_start)

    patch_addr = 0
    for a in possible_addresses:
        itr = iter(md.disasm(code[a:], nav_start+a))

        i = itr.next()
        # print "{:X}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str)
        if i.bytes != '\x85\xC0':  # test eax,eax
            continue

        test_eaxeax_addr = i.address
        i = itr.next()
        # print "{:X}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str)
        if i.mnemonic.lower() not in (['jnz', 'jne'] if stomp_is_isdirty else ['jz', 'je']):
            continue

        patch = '\xff\xc0' if stomp_is_isdirty else '\x31'
        patch_addr = test_eaxeax_addr
        break

    if not patch_addr:
        raise Exception('failed finding address in any of the possible options: {}'.format(
            possible_addresses))
    print 'patching {:X}'.format(patch_addr)
    f.set_bytes_at_rva(patch_addr, patch)
    f.write(outfile)
    print 'done'


def main(infile, outfile, dbg):
    f = PE(infile)

    s = SymSession(debug=dbg, opts=SymOpts.SYMOPT_UNDNAME)
    s.init()
    dllbase = s.load(infile, f.FILE_HEADER.Machine,
                     f.OPTIONAL_HEADER.SizeOfImage, f.OPTIONAL_HEADER.ImageBase)

    # just to preload symbosl and filter out the irrelevant ones
    s.find(dllbase, mask="*CAddressEditBox*")
    stomp_is_isdirty = False
    stomp_func = s.find(dllbase, target=".*_CanStompCurrentText.*")
    if len(stomp_func) == 0:
        stomp_func = s.find(dllbase, target=".*_IsDirty.*")
        stomp_is_isdirty = True  # this happens on win7 x64

    if len(stomp_func) != 1:
        raise Exception(
            'found more/less funcs than unexpected for _CanStompCurrentText: {}'.format(stomp_func))
    stomp_func = stomp_func[0]

    nav_func = s.find(dllbase, target=".*_NavigateAfterParse.*")
    if len(nav_func) != 1:
        raise Exception(
            'found more/less funcs than unexpected for _NavigateAfterParse: {}'.format(nav_func))
    nav_func = nav_func[0]

    s.cleanup()

    if dbg or not outfile:
        # TODO: print version and file info
        print infile
        print '  base: {:X}'.format(dllbase)
        print '  |  +0x{1:X}: {0}'.format(nav_func.Name,
                                          nav_func.Address-dllbase)
        print '  |  +0x{1:X}: {0}'.format(
            stomp_func.Name, stomp_func.Address-dllbase)

    if outfile:
        print 'trying to patching'
        patch(f, outfile, nav_func, stomp_func, stomp_is_isdirty)


if __name__ == '__main__':
    defpath = r'C:\windows\system32\explorerframe.dll'
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', dest='infile',
                        default=defpath, help='(default: %s)' % defpath)

    parser.add_argument('-o', dest='outfile')
    parser.add_argument('-d', help='pass DEBUG option to dbghelp (use dbgview)',
                        dest='debug', default=False, action='store_true')
    # TODO: add logging
    args = parser.parse_args()
    try:
        main(args.infile, args.outfile, args.debug)
    except Exception as e:
        print 'to debug symbol loading pass `-d` and run dbgview'
        print
        raise
