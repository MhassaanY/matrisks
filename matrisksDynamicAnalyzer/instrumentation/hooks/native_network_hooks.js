/**
 * Native Network Hooks - REAL SOLUTION
 * 
 * Problem: Firebase and other SDKs use native C++ networking that bypasses Java
 * Solution: Hook at the socket/send/recv layer where plaintext data flows
 * 
 * This captures EVERYTHING - Java, native, Firebase, Unity, everything
 */

console.log("[*] Loading Native Network Hooks...");

/**
 * Hook libc socket functions to capture ALL network traffic
 * These are the lowest-level functions before data gets encrypted
 */
function hookNativeSocketFunctions() {
    // Find libc.so (contains socket functions)
    var libc = null;
    var libcNames = ["libc.so", "libc.so.6", "libc.so.1"];
    
    for (var i = 0; i < libcNames.length; i++) {
        try {
            libc = Process.getModuleByName(libcNames[i]);
            if (libc) {
                console.log("[+] Found libc at: " + libc.base);
                break;
            }
        } catch (e) {
            continue;
        }
    }
    
    if (!libc) {
        console.log("[-] libc not found, trying alternative method...");
        return false;
    }
    
    // Hook send() - captures outgoing data (requests)
    try {
        var sendPtr = Module.findExportByName(libc.name, "send");
        if (sendPtr) {
            Interceptor.attach(sendPtr, {
                onEnter: function(args) {
                    var sockfd = args[0].toInt32();
                    var buf = args[1];
                    var len = args[2].toInt32();
                    var flags = args[3].toInt32();
                    
                    // Only capture if looks like HTTP/HTTPS
                    if (len > 0 && len < 1000000) {  // Reasonable size
                        try {
                            var data = Memory.readUtf8String(buf, Math.min(len, 4096));
                            
                            // Check if it's HTTP traffic
                            if (data.indexOf('HTTP') !== -1 || 
                                data.indexOf('GET ') === 0 ||
                                data.indexOf('POST ') === 0 ||
                                data.indexOf('PUT ') === 0 ||
                                data.indexOf('Host:') !== -1) {
                                
                                // Parse HTTP request
                                var lines = data.split('\r\n');
                                var requestLine = lines[0];
                                var headers = {};
                                var body = '';
                                
                                // Extract headers
                                var bodyStart = -1;
                                for (var i = 1; i < lines.length; i++) {
                                    if (lines[i] === '') {
                                        bodyStart = i + 1;
                                        break;
                                    }
                                    var colonIdx = lines[i].indexOf(':');
                                    if (colonIdx > 0) {
                                        var key = lines[i].substring(0, colonIdx).trim();
                                        var value = lines[i].substring(colonIdx + 1).trim();
                                        headers[key] = value;
                                    }
                                }
                                
                                // Extract body
                                if (bodyStart >= 0) {
                                    body = lines.slice(bodyStart).join('\r\n');
                                }
                                
                                // Extract method and URL
                                var parts = requestLine.split(' ');
                                var method = parts[0] || 'UNKNOWN';
                                var path = parts[1] || '/';
                                var host = headers['Host'] || 'unknown';
                                var url = 'https://' + host + path;
                                
                                // Send to Python
                                send({
                                    type: 'https_request',
                                    source: 'native_send',
                                    method: method,
                                    url: url,
                                    headers: headers,
                                    body: body,
                                    body_length: body.length,
                                    timestamp: Date.now()
                                });
                                
                                console.log("[+] Native HTTP Request: " + method + " " + url);
                            }
                        } catch (e) {
                            // Not UTF-8 or not HTTP, skip
                        }
                    }
                }
            });
            console.log("[+] Hooked send() for outgoing traffic");
        }
    } catch (e) {
        console.log("[-] Failed to hook send(): " + e);
    }
    
    // Hook recv() - captures incoming data (responses)
    try {
        var recvPtr = Module.findExportByName(libc.name, "recv");
        if (recvPtr) {
            Interceptor.attach(recvPtr, {
                onLeave: function(retval) {
                    var len = retval.toInt32();
                    if (len > 0 && len < 1000000) {
                        try {
                            // Get buffer from first argument (saved in onEnter)
                            if (this.buf) {
                                var data = Memory.readUtf8String(this.buf, Math.min(len, 4096));
                                
                                // Check if it's HTTP response
                                if (data.indexOf('HTTP/') === 0 || data.indexOf('200 OK') !== -1 || data.indexOf('404') !== -1) {
                                    
                                    // Parse HTTP response
                                    var lines = data.split('\r\n');
                                    var statusLine = lines[0];
                                    var headers = {};
                                    var body = '';
                                    
                                    // Extract status code
                                    var statusParts = statusLine.split(' ');
                                    var statusCode = statusParts.length > 1 ? parseInt(statusParts[1]) : 0;
                                    
                                    // Extract headers
                                    var bodyStart = -1;
                                    for (var i = 1; i < lines.length; i++) {
                                        if (lines[i] === '') {
                                            bodyStart = i + 1;
                                            break;
                                        }
                                        var colonIdx = lines[i].indexOf(':');
                                        if (colonIdx > 0) {
                                            var key = lines[i].substring(0, colonIdx).trim();
                                            var value = lines[i].substring(colonIdx + 1).trim();
                                            headers[key] = value;
                                        }
                                    }
                                    
                                    // Extract body
                                    if (bodyStart >= 0) {
                                        body = lines.slice(bodyStart).join('\r\n');
                                    }
                                    
                                    // Send to Python
                                    send({
                                        type: 'https_response',
                                        source: 'native_recv',
                                        status_code: statusCode,
                                        status_text: statusLine,
                                        headers: headers,
                                        body: body,
                                        body_length: body.length,
                                        timestamp: Date.now()
                                    });
                                    
                                    console.log("[+] Native HTTP Response: " + statusCode + " (" + body.length + " bytes)");
                                }
                            }
                        } catch (e) {
                            // Not UTF-8 or not HTTP, skip
                        }
                    }
                },
                onEnter: function(args) {
                    // Save buffer pointer for onLeave
                    this.buf = args[1];
                }
            });
            console.log("[+] Hooked recv() for incoming traffic");
        }
    } catch (e) {
        console.log("[-] Failed to hook recv(): " + e);
    }
    
    return true;
}

/**
 * Hook write/read for SSL sockets (encrypted data on wire, but we hook before encryption)
 * This catches SSL_write and SSL_read from BoringSSL/OpenSSL
 */
function hookSSLFunctions() {
    var sslLibs = ["libssl.so", "libssl.so.1.1", "libssl.so.1.0.0", "libboringssl.so"];
    var sslLib = null;
    
    for (var i = 0; i < sslLibs.length; i++) {
        try {
            sslLib = Process.getModuleByName(sslLibs[i]);
            if (sslLib) {
                console.log("[+] Found SSL library: " + sslLib.name + " at " + sslLib.base);
                break;
            }
        } catch (e) {
            continue;
        }
    }
    
    if (!sslLib) {
        console.log("[-] SSL library not found");
        return false;
    }
    
    // Hook SSL_write (outgoing HTTPS data - PLAINTEXT before encryption!)
    try {
        var SSL_write = Module.findExportByName(sslLib.name, "SSL_write");
        if (SSL_write) {
            Interceptor.attach(SSL_write, {
                onEnter: function(args) {
                    var ssl = args[0];
                    var buf = args[1];
                    var num = args[2].toInt32();
                    
                    if (num > 0 && num < 100000) {
                        try {
                            // Read PLAINTEXT data before it gets encrypted
                            var data = Memory.readUtf8String(buf, Math.min(num, 4096));
                            
                            if (data.indexOf('HTTP') !== -1 || data.indexOf('POST ') === 0 || data.indexOf('GET ') === 0) {
                                console.log("[+] SSL_write captured (" + num + " bytes plaintext)");
                                
                                // Parse as HTTP
                                var lines = data.split('\r\n');
                                var requestLine = lines[0];
                                var parts = requestLine.split(' ');
                                var method = parts[0] || 'UNKNOWN';
                                var path = parts[1] || '/';
                                
                                // Extract headers
                                var headers = {};
                                var body = '';
                                var bodyStart = -1;
                                for (var i = 1; i < lines.length; i++) {
                                    if (lines[i] === '') {
                                        bodyStart = i + 1;
                                        break;
                                    }
                                    var colonIdx = lines[i].indexOf(':');
                                    if (colonIdx > 0) {
                                        headers[lines[i].substring(0, colonIdx)] = lines[i].substring(colonIdx + 1).trim();
                                    }
                                }
                                if (bodyStart >= 0) {
                                    body = lines.slice(bodyStart).join('\r\n');
                                }
                                
                                var host = headers['Host'] || 'unknown';
                                var url = 'https://' + host + path;
                                
                                send({
                                    type: 'https_request',
                                    source: 'SSL_write',
                                    method: method,
                                    url: url,
                                    headers: headers,
                                    body: body,
                                    body_length: body.length,
                                    timestamp: Date.now()
                                });
                                
                                console.log("[+] SSL Request: " + method + " " + url);
                            }
                        } catch (e) {
                            // Binary or corrupted data
                        }
                    }
                }
            });
            console.log("[+] Hooked SSL_write() - captures plaintext BEFORE encryption!");
        }
    } catch (e) {
        console.log("[-] Failed to hook SSL_write: " + e);
    }
    
    // Hook SSL_read (incoming HTTPS data - PLAINTEXT after decryption!)
    try {
        var SSL_read = Module.findExportByName(sslLib.name, "SSL_read");
        if (SSL_read) {
            Interceptor.attach(SSL_read, {
                onLeave: function(retval) {
                    var len = retval.toInt32();
                    if (len > 0 && len < 100000 && this.buf) {
                        try {
                            // Read PLAINTEXT data after it's been decrypted
                            var data = Memory.readUtf8String(this.buf, Math.min(len, 4096));
                            
                            if (data.indexOf('HTTP/') === 0 || data.indexOf('200 OK') !== -1 || data.indexOf('{') === 0) {
                                console.log("[+] SSL_read captured (" + len + " bytes plaintext)");
                                
                                // Parse as HTTP response
                                var lines = data.split('\r\n');
                                var statusLine = lines[0];
                                var statusParts = statusLine.split(' ');
                                var statusCode = statusParts.length > 1 ? parseInt(statusParts[1]) : 0;
                                
                                // Extract headers and body
                                var headers = {};
                                var body = '';
                                var bodyStart = -1;
                                for (var i = 1; i < lines.length; i++) {
                                    if (lines[i] === '') {
                                        bodyStart = i + 1;
                                        break;
                                    }
                                    var colonIdx = lines[i].indexOf(':');
                                    if (colonIdx > 0) {
                                        headers[lines[i].substring(0, colonIdx)] = lines[i].substring(colonIdx + 1).trim();
                                    }
                                }
                                if (bodyStart >= 0) {
                                    body = lines.slice(bodyStart).join('\r\n');
                                }
                                
                                send({
                                    type: 'https_response',
                                    source: 'SSL_read',
                                    status_code: statusCode,
                                    status_text: statusLine,
                                    headers: headers,
                                    body: body,
                                    body_length: body.length,
                                    timestamp: Date.now()
                                });
                                
                                console.log("[+] SSL Response: " + statusCode + " (" + len + " bytes)");
                            }
                        } catch (e) {
                            // Binary or corrupted data
                        }
                    }
                },
                onEnter: function(args) {
                    // Save buffer for onLeave
                    this.buf = args[1];
                }
            });
            console.log("[+] Hooked SSL_read() - captures plaintext AFTER decryption!");
        }
    } catch (e) {
        console.log("[-] Failed to hook SSL_read: " + e);
    }
    
    return true;
}

// Initialize hooks
Java.perform(function() {
    console.log("[*] Initializing native network hooks...");
    
    // Try SSL hooks first (most reliable for HTTPS)
    var sslHooked = hookSSLFunctions();
    
    // Then socket-level hooks (fallback)
    var socketHooked = hookNativeSocketFunctions();
    
    if (sslHooked || socketHooked) {
        console.log("[+] Native network hooks installed successfully!");
        console.log("[+] Will capture:");
        if (sslHooked) console.log("    - SSL_write/SSL_read (HTTPS plaintext)");
        if (socketHooked) console.log("    - send/recv (all network)");
    } else {
        console.log("[-] Failed to install native hooks");
    }
});
