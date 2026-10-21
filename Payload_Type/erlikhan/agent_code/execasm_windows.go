//go:build windows

package main

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// In-process .NET execution via CLR hosting. The assembly is staged to a
// temp path (deleted after the run), loaded through mscoree into the
// default AppDomain, and executed with stdout/stderr redirected to pipes
// that are drained concurrently. Only syscall/unsafe are used: the agent
// builds with CGO_ENABLED=0 and GOPROXY=off, so no CLR helper library.
//
// Known limit: .NET caches the Console writer per process, so output
// capture is reliable for the first execution in a callback; later runs
// in the same process may lose Console output. (A future fix is
// Console.SetOut through IDispatch before each run.)

var (
	procCLRCreateInstance = syscall.NewLazyDLL("mscoree.dll").NewProc("CLRCreateInstance")

	ole32dll             = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx   = ole32dll.NewProc("CoInitializeEx")
	procCoUninitialize   = ole32dll.NewProc("CoUninitialize")
	oleaut32dll          = syscall.NewLazyDLL("oleaut32.dll")
	procSafeArrayCreate  = oleaut32dll.NewProc("SafeArrayCreateVector")
	procSafeArrayPut     = oleaut32dll.NewProc("SafeArrayPutElement")
	procSafeArrayDestroy = oleaut32dll.NewProc("SafeArrayDestroy")
	procSysAllocString   = oleaut32dll.NewProc("SysAllocString")
	procSysFreeString    = oleaut32dll.NewProc("SysFreeString")

	kernel32dll       = syscall.NewLazyDLL("kernel32.dll")
	procCreatePipe    = kernel32dll.NewProc("CreatePipe")
	procSetStdHandle  = kernel32dll.NewProc("SetStdHandle")
	procGetStdHandle  = kernel32dll.NewProc("GetStdHandle")
	procLocalFree     = kernel32dll.NewProc("LocalFree")
	procCommandLineTo = syscall.NewLazyDLL("shell32.dll").NewProc("CommandLineToArgvW")
)

var (
	clsidCLRMetaHost = syscall.GUID{Data1: 0x9280188D, Data2: 0x0E8E, Data3: 0x4867,
		Data4: [8]byte{0xB3, 0x0C, 0x7F, 0x86, 0xA9, 0xE8, 0x94, 0x6E}}
	iidICLRMetaHost = syscall.GUID{Data1: 0xD332DB9E, Data2: 0xB9B3, Data3: 0x4125,
		Data4: [8]byte{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x96}}
	iidICLRRuntimeInfo = syscall.GUID{Data1: 0xBD39D1D2, Data2: 0xBA2F, Data3: 0x486A,
		Data4: [8]byte{0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x62, 0x91}}
	clsidCorRuntimeHost = syscall.GUID{Data1: 0xCB2F6723, Data2: 0xAB3A, Data3: 0x11D2,
		Data4: [8]byte{0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}}
	iidICorRuntimeHost = syscall.GUID{Data1: 0xCB2F6722, Data2: 0xAB3A, Data3: 0x11D2,
		Data4: [8]byte{0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}}
	iidIDispatch = syscall.GUID{Data1: 0x00020400, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidNull = syscall.GUID{}
)

const (
	vtableGetRuntime       = 3 // ICLRMetaHost
	vtableRTGetInterface   = 9 // ICLRRuntimeInfo
	vtableHostStart        = 10
	vtableGetDefaultDomain = 13 // ICorRuntimeHost
	vtableRelease          = 2  // IUnknown
	vtableGetIDsOfNames    = 5  // IDispatch
	vtableInvoke           = 6

	vtBSTR            = 8
	vtArrayBSTR       = 0x2008
	dispatchMethod    = 1
	localeUserDefault = 0x400

	stdOutputHandle = ^uintptr(10) // -11
	stdErrorHandle  = ^uintptr(11) // -12

	rpcChangedMode = 0x80010106
)

// comMethod returns one vtable entry of a COM object.
func comMethod(obj unsafe.Pointer, index int) uintptr {
	vt := *(*uintptr)(obj)
	return *(*uintptr)(unsafe.Pointer(vt + uintptr(index)*unsafe.Sizeof(uintptr(0))))
}

func comRelease(obj unsafe.Pointer) {
	if obj != nil {
		syscall.SyscallN(comMethod(obj, vtableRelease), uintptr(obj))
	}
}

func failed(hr uintptr) bool { return int32(hr) < 0 }

func hresultErr(stage string, hr uintptr) error {
	return fmt.Errorf("clr: %s: HRESULT 0x%08x", stage, uint32(hr))
}

// variant16 is a 16-byte VARIANT holding a BSTR or SAFEARRAY pointer.
type variant16 struct {
	vt       uint16
	reserved [3]uint16
	ptr      uintptr
}

func bstrVariant(bstr uintptr) variant16 { return variant16{vt: vtBSTR, ptr: bstr} }
func arrayVariant(arr uintptr) variant16 { return variant16{vt: vtArrayBSTR, ptr: arr} }

type dispparams struct {
	rgvarg            *variant16
	rgdispidNamedArgs uintptr
	cArgs             uint32
	cNamedArgs        uint32
}

// splitAsmArgs splits an argument string the way the CRT would, so quoted
// segments survive into Main(string[]).
func splitAsmArgs(argString string) ([]string, error) {
	if strings.TrimSpace(argString) == "" {
		return nil, nil
	}
	wide, err := syscall.UTF16PtrFromString(argString)
	if err != nil {
		return nil, err
	}
	var argc int32
	r1, _, _ := procCommandLineTo.Call(uintptr(unsafe.Pointer(wide)), uintptr(unsafe.Pointer(&argc)))
	if r1 == 0 {
		return nil, fmt.Errorf("clr: CommandLineToArgvW failed")
	}
	defer procLocalFree.Call(r1)
	argv := (*[1 << 20]uintptr)(unsafe.Pointer(r1))
	out := make([]string, 0, argc)
	for i := int32(0); i < argc; i++ {
		out = append(out, syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(argv[i]))[:]))
	}
	return out, nil
}

func allocBSTR(s string) (uintptr, error) {
	wide, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return 0, err
	}
	r1, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(wide)))
	if r1 == 0 {
		return 0, fmt.Errorf("clr: SysAllocString failed")
	}
	return r1, nil
}

// makeStrArray builds a SAFEARRAY of BSTR, one element per argument.
func makeStrArray(items []string) (uintptr, error) {
	r1, _, _ := procSafeArrayCreate.Call(vtBSTR, 0, uintptr(len(items)))
	if r1 == 0 {
		return 0, fmt.Errorf("clr: SafeArrayCreateVector failed")
	}
	for i, s := range items {
		bstr, err := allocBSTR(s)
		if err != nil {
			procSafeArrayDestroy.Call(r1)
			return 0, err
		}
		idx := int32(i)
		put, _, _ := procSafeArrayPut.Call(r1, uintptr(unsafe.Pointer(&idx)), bstr)
		procSysFreeString.Call(bstr) // PutElement copies BSTRs.
		if int32(put) < 0 {
			procSafeArrayDestroy.Call(r1)
			return 0, fmt.Errorf("clr: SafeArrayPutElement: HRESULT 0x%08x", uint32(put))
		}
	}
	return r1, nil
}

// dispInvoke calls one IDispatch method. Args run last-to-first in rgvarg
// per COM convention.
func dispInvoke(disp unsafe.Pointer, dispid int32, args ...variant16) uintptr {
	rev := make([]variant16, len(args))
	for i, a := range args {
		rev[len(args)-1-i] = a
	}
	dp := dispparams{cArgs: uint32(len(rev))}
	if len(rev) > 0 {
		dp.rgvarg = &rev[0]
	}
	var result variant16
	r1, _, _ := syscall.SyscallN(comMethod(disp, vtableInvoke),
		uintptr(disp), uintptr(dispid), uintptr(unsafe.Pointer(&iidNull)),
		localeUserDefault, dispatchMethod, uintptr(unsafe.Pointer(&dp)),
		uintptr(unsafe.Pointer(&result)), 0, 0)
	return r1
}

// pipeCapture redirects one std handle to a pipe and drains it on a
// goroutine. Close stops the drain and returns everything read.
type pipeCapture struct {
	handle syscall.Handle
	read   syscall.Handle
	write  syscall.Handle
	old    uintptr
	buf    []byte
	wg     sync.WaitGroup
}

func captureStd(nstd uintptr) (*pipeCapture, error) {
	c := &pipeCapture{handle: syscall.InvalidHandle}
	old, _, _ := procGetStdHandle.Call(nstd)
	c.old = old
	r1, _, _ := procCreatePipe.Call(
		uintptr(unsafe.Pointer(&c.read)), uintptr(unsafe.Pointer(&c.write)), 0, 0)
	if r1 == 0 {
		return nil, fmt.Errorf("clr: CreatePipe failed")
	}
	if r1, _, _ := procSetStdHandle.Call(nstd, uintptr(c.write)); r1 == 0 {
		syscall.CloseHandle(c.read)
		syscall.CloseHandle(c.write)
		return nil, fmt.Errorf("clr: SetStdHandle failed")
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		chunk := make([]byte, 8192)
		for {
			n, err := syscall.Read(c.read, chunk)
			if n > 0 {
				c.buf = append(c.buf, chunk[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()
	return c, nil
}

func (c *pipeCapture) finish(nstd uintptr) string {
	syscall.CloseHandle(c.write) // EOF for the drainer.
	c.wg.Wait()
	procSetStdHandle.Call(nstd, c.old)
	syscall.CloseHandle(c.read)
	out := string(c.buf)
	c.buf = nil
	return out
}

func runAssemblyInProcess(path string, argString string) (string, error) {
	// COM apartments are per-thread and Go migrates goroutines: pin this
	// one for the whole CLR sequence.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	argv, err := splitAsmArgs(argString)
	if err != nil {
		return "", err
	}
	hr, _, _ := procCoInitializeEx.Call(0, 0)
	initialized := hr == 0 || hr == 1 // S_OK or S_FALSE.
	if failed(hr) && hr != rpcChangedMode {
		return "", hresultErr("CoInitializeEx", hr)
	}
	if initialized {
		defer procCoUninitialize.Call()
	}

	var meta, rtInfo, host, domain, disp unsafe.Pointer
	defer comRelease(meta)
	defer comRelease(rtInfo)
	defer comRelease(host)
	defer comRelease(domain)
	defer comRelease(disp)

	runtimePath, err := syscall.UTF16PtrFromString("v4.0.30319")
	if err != nil {
		return "", err
	}
	if hr, _, _ := procCLRCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidCLRMetaHost)),
		uintptr(unsafe.Pointer(&iidICLRMetaHost)),
		uintptr(unsafe.Pointer(&meta))); failed(hr) {
		return "", hresultErr("CLRCreateInstance", hr)
	}
	if hr, _, _ := syscall.SyscallN(comMethod(meta, vtableGetRuntime),
		uintptr(meta), uintptr(unsafe.Pointer(runtimePath)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeInfo)),
		uintptr(unsafe.Pointer(&rtInfo))); failed(hr) {
		return "", hresultErr("GetRuntime(v4.0.30319)", hr)
	}
	if hr, _, _ := syscall.SyscallN(comMethod(rtInfo, vtableRTGetInterface),
		uintptr(rtInfo), uintptr(unsafe.Pointer(&clsidCorRuntimeHost)),
		uintptr(unsafe.Pointer(&iidICorRuntimeHost)),
		uintptr(unsafe.Pointer(&host))); failed(hr) {
		return "", hresultErr("GetInterface(CorRuntimeHost)", hr)
	}
	if hr, _, _ := syscall.SyscallN(comMethod(host, vtableHostStart),
		uintptr(host)); failed(hr) {
		return "", hresultErr("CorRuntimeHost.Start", hr)
	}
	if hr, _, _ := syscall.SyscallN(comMethod(host, vtableGetDefaultDomain),
		uintptr(host), uintptr(unsafe.Pointer(&domain))); failed(hr) {
		return "", hresultErr("GetDefaultDomain", hr)
	}
	if hr, _, _ := syscall.SyscallN(comMethod(domain, 0), // QueryInterface
		uintptr(domain), uintptr(unsafe.Pointer(&iidIDispatch)),
		uintptr(unsafe.Pointer(&disp))); failed(hr) {
		return "", hresultErr("AppDomain IDispatch", hr)
	}
	name, err := syscall.UTF16PtrFromString("ExecuteAssembly")
	if err != nil {
		return "", err
	}
	var dispid int32
	names := []*uint16{name}
	if hr, _, _ := syscall.SyscallN(comMethod(disp, vtableGetIDsOfNames),
		uintptr(disp), uintptr(unsafe.Pointer(&iidNull)),
		uintptr(unsafe.Pointer(&names[0])), 1, localeUserDefault,
		uintptr(unsafe.Pointer(&dispid))); failed(hr) {
		return "", hresultErr("ExecuteAssembly dispid", hr)
	}

	pathBSTR, err := allocBSTR(path)
	if err != nil {
		return "", err
	}
	defer procSysFreeString.Call(pathBSTR)
	var argArray uintptr
	if len(argv) > 0 {
		argArray, err = makeStrArray(argv)
		if err != nil {
			return "", err
		}
		defer procSafeArrayDestroy.Call(argArray)
	}

	stdout, err := captureStd(stdOutputHandle)
	if err != nil {
		return "", err
	}
	stderr, err := captureStd(stdErrorHandle)
	if err != nil {
		stdout.finish(stdOutputHandle)
		return "", err
	}
	// _AppDomain.ExecuteAssembly is overloaded and IDispatch resolves one
	// dispid for the name, so probe arities from most to least specific:
	// (path, evidence, args), (path, evidence), (path). A failed Invoke
	// has no side effects, so the first success wins.
	invoke := func(args ...variant16) uintptr { return dispInvoke(disp, dispid, args...) }
	var hv uintptr
	empty := variant16{} // VT_EMPTY evidence.
	switch {
	case len(argv) > 0:
		hv = invoke(bstrVariant(pathBSTR), empty, arrayVariant(argArray))
		if failed(hv) {
			hv = invoke(bstrVariant(pathBSTR), empty)
		}
		if failed(hv) {
			hv = invoke(bstrVariant(pathBSTR))
		}
	default:
		hv = invoke(bstrVariant(pathBSTR))
	}
	out := stdout.finish(stdOutputHandle)
	errOut := stderr.finish(stdErrorHandle)
	if errOut != "" {
		if out != "" {
			out += "\n"
		}
		out += errOut
	}
	if failed(hv) {
		return "", hresultErr("ExecuteAssembly invoke", hv)
	}
	return out, nil
}
