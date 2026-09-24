"""LLDB trace for privacy-safe Emoticon cache open call stacks."""
import lldb


_hits = 0


def _path_argument(frame):
    name = frame.GetFunctionName() or ""
    register = "x1" if "openat" in name else "x0"
    value = frame.FindRegister(register).GetValueAsUnsigned()
    if not value:
        return None
    error = lldb.SBError()
    path = frame.GetThread().GetProcess().ReadCStringFromMemory(value, 4096, error)
    return path if error.Success() else None


def cache_open_callback(frame, _location, _dictionary):
    global _hits
    path = _path_argument(frame)
    if not path or "/Emoticon/" not in path:
        return False
    _hits += 1
    target = frame.GetThread().GetProcess().GetTarget()
    entries = []
    for stack_frame in frame.GetThread():
        module = stack_frame.GetModule()
        module_path = module.file.fullpath if module.IsValid() else ""
        if not module_path.endswith("/Resources/wechat.dylib"):
            continue
        header = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
        pc = stack_frame.GetPCAddress().GetLoadAddress(target)
        entries.append("core+0x{:x}".format(pc - header))
        if len(entries) >= 16:
            break
    print("EMOTICON_OPEN_TRACE hit={} stack={}".format(
        _hits, ",".join(entries) if entries else "none"
    ))
    return False


def install(debugger, _command, result, _dictionary):
    target = debugger.GetSelectedTarget()
    installed = []
    for name in ("open", "open$NOCANCEL", "openat", "openat$NOCANCEL", "fopen"):
        breakpoint = target.BreakpointCreateByName(name)
        if not breakpoint.IsValid() or breakpoint.GetNumLocations() == 0:
            target.BreakpointDelete(breakpoint.GetID())
            continue
        breakpoint.SetScriptCallbackFunction(
            "emoticon_open_trace.cache_open_callback"
        )
        installed.append("{}:{}".format(name, breakpoint.GetNumLocations()))
    result.AppendMessage("EMOTICON_OPEN_TRACE ready={}".format(
        ",".join(installed) if installed else "none"
    ))


def __lldb_init_module(debugger, _dictionary):
    debugger.HandleCommand(
        "command script add -f emoticon_open_trace.install emoticon-open-trace"
    )
