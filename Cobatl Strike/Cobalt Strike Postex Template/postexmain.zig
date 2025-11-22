const std = @import("std");
const postex = @import("postex.zig");
const win = std.os.windows;

pub fn postexMain(postexData: postex.PostexData) void {
    postex.Beacon.beaconPrintf(postex.CALLBACK_OUTPUT, "maxPacketSize : {d}", .{postexData.pPostexArguments.maxPacketSize});
    postex.Beacon.beaconPrintf(postex.CALLBACK_OUTPUT, "MAX_PACKET_SIZE : {d}", .{postex.MAX_PACKET_SIZE});
    postex.Beacon.beaconPrintf(postex.CALLBACK_OUTPUT, "userArgumentBufferSize : {d}", .{postexData.pPostexArguments.userArgumentBufferSize});
    postex.Beacon.beaconPrintf(postex.CALLBACK_ERROR, "Skill issue", .{});

    var counter: u32 = 0;
    while (true) {
        postex.Beacon.beaconPrintf(postex.CALLBACK_OUTPUT, "Counter : {d}", .{counter});
        counter += 1;
        std.Thread.sleep(postex.nanoToMili(3000));
        if (!postex.Pipes.clientConnected(postex.gPipeHandle)) break;
    }

    return;
}

pub fn DllMain(hModule: win.HINSTANCE, ul_reason_for_call: win.DWORD, lpReserved: win.LPVOID) win.BOOL {
    const startPipeServer = 0;
    return postex.dllEntryPoint(@ptrCast(hModule), ul_reason_for_call, lpReserved, startPipeServer);
}
