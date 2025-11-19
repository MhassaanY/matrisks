/**
 * Enhanced API Monitor with HTTPS Interception
 * Phase 2.5: Lightweight HTTPS decryption without mitmproxy
 * 
 * Strategy: Hook at Java layer BEFORE encryption happens
 * Coverage: HttpURLConnection (20%) + OkHttp (65%) + SSLSocket (10%) = 95%
 */

console.log("[*] Enhanced API Monitor with HTTPS Interception loaded");

// Global flags for intelligent hook selection
var appUseCronet = false;
var sslUnpinningEnabled = false;

// Message handler to receive commands from Python
recv('config', function(config) {
    console.log("[*] Received configuration from Python:");
    if (config.enable_mitm) {
        sslUnpinningEnabled = true;
        console.log("[+] MITM mode enabled - SSL unpinning will be activated");
    }
    if (config.proxy_host && config.proxy_port) {
        console.log("[+] Proxy configured: " + config.proxy_host + ":" + config.proxy_port);
        // Proxy routing will be handled by mitmproxy at system level
    }
});

// Track hooked APIs
var hookedAPIs = {
    network: [],
    https: [],
    file: [],
    crypto: [],
    sms: [],
    location: [],
    contacts: [],
    runtime: [],
    classLoader: []
};

/**
 * Helper: Send data back to Python
 */
function sendData(category, action, details) {
    send({
        category: category,
        action: action,
        timestamp: Date.now(),
        details: details
    });
}

/**
 * Helper: Convert byte array to string safely
 */
function bytesToString(bytes) {
    try {
        var str = '';
        for (var i = 0; i < Math.min(bytes.length, 10000); i++) {  // Limit to 10KB to avoid memory issues
            var byte = bytes[i] & 0xFF;
            if (byte >= 32 && byte <= 126) {
                str += String.fromCharCode(byte);
            } else if (byte === 10 || byte === 13) {
                str += '\n';
            } else {
                str += '.';
            }
        }
        return str;
    } catch (e) {
        return '[Binary data - ' + bytes.length + ' bytes]';
    }
}

/**
 * Detect if app uses Cronet (Chrome networking stack)
 * Cronet bypasses traditional TLS hooks, requiring MITM approach
 * 
 * Uses delayed detection because native libraries load after Java code
 */
function detectCronet() {
    var detected = false;
    
    // Immediate check (for already-loaded libraries)
    try {
        var cronetModule = Process.findModuleByName("libcronet.so");
        if (cronetModule) {
            detected = true;
            appUseCronet = true;
            console.log("[!] ========================================");
            console.log("[!] CRONET DETECTED: " + cronetModule.path);
            console.log("[!] App uses Chrome networking stack (gRPC)");
            console.log("[!] Traditional hooks cannot capture bodies");
            console.log("[!] ========================================");
            
            send({
                type: 'cronet_detected',
                path: cronetModule.path,
                base: cronetModule.base.toString(),
                size: cronetModule.size
            });
        }
    } catch (e) {
        // Library not loaded yet
    }
    
    // Delayed check (wait for native libraries to load)
    setTimeout(function() {
        try {
            var cronetModule = Process.findModuleByName("libcronet.so");
            if (cronetModule && !appUseCronet) {
                appUseCronet = true;
                console.log("[!] ========================================");
                console.log("[!] CRONET DETECTED (delayed): " + cronetModule.path);
                console.log("[!] App uses Chrome networking stack (gRPC)");
                console.log("[!] Traditional hooks cannot capture bodies");
                console.log("[!] ========================================");
                
                send({
                    type: 'cronet_detected',
                    path: cronetModule.path,
                    base: cronetModule.base.toString(),
                    size: cronetModule.size
                });
            }
            
            // Also check for gRPC libraries
            var grpcModule = Process.findModuleByName("libgrpc.so");
            if (grpcModule) {
                console.log("[!] gRPC library detected: " + grpcModule.path);
                send({
                    type: 'grpc_detected',
                    path: grpcModule.path
                });
            }
            
            if (!appUseCronet) {
                console.log("[+] No Cronet detected - standard TLS hooks will work");
            }
        } catch (e) {
            console.log("[-] Delayed Cronet detection failed: " + e);
        }
    }, 5000);  // Check again after 5 seconds
    
    return detected;
}

/**
 * SSL Certificate Pinning Bypass (only enabled for Cronet apps when MITM mode is active)
 * This allows MITM proxy to intercept HTTPS traffic for apps that use Cronet
 */
function enableSSLUnpinning() {
    if (!sslUnpinningEnabled) {
        return; // Skip if not explicitly enabled
    }
    
    try {
        console.log("[*] Enabling SSL unpinning (MITM mode)...");
        
        // Bypass TrustManagerImpl certificate verification
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log("[+] Bypassing certificate verification for: " + host);
                return untrustedChain;
            };
            console.log("[+] TrustManagerImpl.verifyChain bypassed");
        } catch (e) {
            console.log("[-] TrustManagerImpl not found: " + e);
        }
        
        // Bypass SSLContext certificate verification
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var TrustManager = Java.use("javax.net.ssl.TrustManager");
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            
            var X509TrustManagerImpl = Java.registerClass({
                name: 'com.matrisks.X509TrustManagerImpl',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() {
                        return [];
                    }
                }
            });
            
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, secureRandom) {
                console.log("[+] SSLContext.init() called - injecting custom TrustManager");
                var customTrustManager = X509TrustManagerImpl.$new();
                this.init(keyManager, [customTrustManager], secureRandom);
            };
            console.log("[+] SSLContext.init bypassed");
        } catch (e) {
            console.log("[-] SSLContext bypass failed: " + e);
        }
        
        // Bypass OkHttp certificate pinning
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                console.log("[+] Bypassing OkHttp certificate pinning for: " + hostname);
                return;
            };
            console.log("[+] OkHttp CertificatePinner bypassed");
        } catch (e) {
            console.log("[-] OkHttp not found: " + e);
        }
        
        console.log("[+] SSL unpinning enabled successfully");
        
    } catch (e) {
        console.log("[-] SSL unpinning failed: " + e);
    }
}

/**
 * HTTPS Interception: HttpURLConnection
 * Hooks: getOutputStream (request), getInputStream (response)
 */
function hookHttpURLConnectionHTTPS() {
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
        var BufferedReader = Java.use("java.io.BufferedReader");
        var InputStreamReader = Java.use("java.io.InputStreamReader");
        var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
        
        // Hook getOutputStream to capture request body
        HttpURLConnection.getOutputStream.implementation = function() {
            var stream = this.getOutputStream();
            var url = this.getURL().toString();
            var method = this.getRequestMethod();
            
            // Only intercept HTTPS
            if (!url.startsWith('https://')) {
                return stream;
            }
            
            console.log("[*] Intercepting HTTPS request: " + method + " " + url);
            
            // Create capture stream
            var captureStream = ByteArrayOutputStream.$new();
            var streamClosed = false;
            
            // Wrap write methods
            var originalWrite1 = stream.write.overload('int');
            var originalWrite2 = stream.write.overload('[B');
            var originalWrite3 = stream.write.overload('[B', 'int', 'int');
            var originalClose = stream.close;
            
            stream.write.overload('int').implementation = function(b) {
                captureStream.write(b);
                return originalWrite1.call(this, b);
            };
            
            stream.write.overload('[B').implementation = function(b) {
                captureStream.write(b);
                return originalWrite2.call(this, b);
            };
            
            stream.write.overload('[B', 'int', 'int').implementation = function(b, off, len) {
                captureStream.write(b, off, len);
                return originalWrite3.call(this, b, off, len);
            };
            
            stream.close.implementation = function() {
                if (!streamClosed) {
                    streamClosed = true;
                    var requestBody = captureStream.toString('UTF-8');
                    
                    sendData('https', 'HTTPS_REQUEST', {
                        protocol: 'HttpURLConnection',
                        url: url,
                        method: method,
                        body: requestBody,
                        body_length: captureStream.size()
                    });
                }
                return originalClose.call(this);
            };
            
            return stream;
        };
        
        // Hook getInputStream to capture response body  
        HttpURLConnection.getInputStream.implementation = function() {
            var stream = this.getInputStream();
            var url = this.getURL().toString();
            
            // Only intercept HTTPS
            if (!url.startsWith('https://')) {
                return stream;
            }
            
            var responseCode = -1;
            try {
                responseCode = this.getResponseCode();
            } catch (e) {
                responseCode = -1;
            }
            
            console.log("[*] Intercepting HTTPS response: " + responseCode + " " + url);
            
            // Read entire response
            try {
                var reader = BufferedReader.$new(InputStreamReader.$new(stream));
                var response = '';
                var line = null;
                var lineCount = 0;
                
                while ((line = reader.readLine()) != null && lineCount < 1000) {  // Limit lines to prevent hangs
                    response += line + '\n';
                    lineCount++;
                }
                
                sendData('https', 'HTTPS_RESPONSE', {
                    protocol: 'HttpURLConnection',
                    url: url,
                    status_code: responseCode,
                    body: response,
                    body_length: response.length,
                    truncated: lineCount >= 1000
                });
                
                // Return new stream with same data
                return ByteArrayInputStream.$new(response.getBytes('UTF-8'));
                
            } catch (e) {
                console.log("[-] Error reading HTTPS response: " + e);
                return stream;  // Return original stream on error
            }
        };
        
        hookedAPIs.https.push("HttpURLConnection HTTPS");
        console.log("[+] HttpURLConnection HTTPS hooks installed");
        
    } catch (e) {
        console.log("[-] Error hooking HttpURLConnection HTTPS: " + e);
    }
}

/**
 * HTTPS Interception: OkHttp3
 * Most modern apps use OkHttp - this is critical for coverage
 */
function hookOkHttpHTTPS() {
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Interceptor = Java.use("okhttp3.Interceptor");
        var Response = Java.use("okhttp3.Response");
        var ResponseBody = Java.use("okhttp3.ResponseBody");
        var MediaType = Java.use("okhttp3.MediaType");
        
        // Hook OkHttpClient.Builder.build() to inject our interceptor
        var Builder = Java.use("okhttp3.OkHttpClient$Builder");
        var originalBuild = Builder.build;
        
        Builder.build.implementation = function() {
            var client = originalBuild.call(this);
            
            // Create our interceptor
            var FridaInterceptor = Java.registerClass({
                name: 'com.matrisks.FridaHTTPSInterceptor',
                implements: [Interceptor],
                methods: {
                    intercept: function(chain) {
                        var request = chain.request();
                        var url = request.url().toString();
                        
                        // Only intercept HTTPS
                        if (!url.startsWith('https://')) {
                            return chain.proceed(request);
                        }
                        
                        var method = request.method();
                        var headers = request.headers().toString();
                        
                        // Capture request body
                        var requestBody = request.body();
                        var requestBodyString = '';
                        
                        if (requestBody != null) {
                            try {
                                var Buffer = Java.use("okio.Buffer");
                                var buffer = Buffer.$new();
                                requestBody.writeTo(buffer);
                                requestBodyString = buffer.readUtf8();
                                
                                sendData('https', 'HTTPS_REQUEST', {
                                    protocol: 'OkHttp3',
                                    url: url,
                                    method: method,
                                    headers: headers,
                                    body: requestBodyString,
                                    body_length: requestBodyString.length
                                });
                            } catch (e) {
                                console.log("[-] Error reading OkHttp request body: " + e);
                            }
                        } else {
                            sendData('https', 'HTTPS_REQUEST', {
                                protocol: 'OkHttp3',
                                url: url,
                                method: method,
                                headers: headers,
                                body: '',
                                body_length: 0
                            });
                        }
                        
                        // Proceed with request
                        var response = chain.proceed(request);
                        
                        // Capture response body
                        var responseBody = response.body();
                        var responseBodyString = '';
                        
                        if (responseBody != null) {
                            try {
                                responseBodyString = responseBody.string();
                                
                                sendData('https', 'HTTPS_RESPONSE', {
                                    protocol: 'OkHttp3',
                                    url: url,
                                    status_code: response.code(),
                                    headers: response.headers().toString(),
                                    body: responseBodyString,
                                    body_length: responseBodyString.length
                                });
                                
                                // Rebuild response with same body for app to consume
                                var contentType = responseBody.contentType();
                                var newBody = ResponseBody.create(contentType, responseBodyString);
                                response = response.newBuilder().body(newBody).build();
                                
                            } catch (e) {
                                console.log("[-] Error reading OkHttp response body: " + e);
                            }
                        }
                        
                        return response;
                    }
                }
            });
            
            // Add our interceptor to the client
            try {
                client.interceptors().add(FridaInterceptor.$new());
                console.log("[*] OkHttp HTTPS interceptor added");
            } catch (e) {
                console.log("[-] Failed to add OkHttp interceptor: " + e);
            }
            
            return client;
        };
        
        hookedAPIs.https.push("OkHttp3 HTTPS");
        console.log("[+] OkHttp3 HTTPS hooks installed");
        
    } catch (e) {
        console.log("[!] OkHttp3 not available or hook failed: " + e);
    }
}

/**
 * Hook SSLSocket Output/InputStream (Conscrypt - catches Firebase and native HTTPS)
 * This is the lowest Java-level hook before data goes to native TLS
 */
function hookSSLSocketStreams() {
    try {
        // Try to hook Conscrypt's actual implementation classes
        var sslSocketClasses = [
            "com.android.org.conscrypt.ConscryptFileDescriptorSocket",
            "com.android.org.conscrypt.OpenSSLSocketImpl",
            "org.conscrypt.ConscryptFileDescriptorSocket",
            "org.conscrypt.OpenSSLSocketImpl",
            "javax.net.ssl.SSLSocket"
        ];
        
        var hookedClass = null;
        var SSLSocket = null;
        
        for (var i = 0; i < sslSocketClasses.length; i++) {
            try {
                SSLSocket = Java.use(sslSocketClasses[i]);
                hookedClass = sslSocketClasses[i];
                console.log("[+] Found SSL socket class: " + hookedClass);
                break;
            } catch (e) {
                // Class not found, try next
            }
        }
        
        if (!SSLSocket) {
            console.log("[-] No SSL socket implementation found");
            return;
        }
        
        // Hook getOutputStream to capture HTTPS requests (plaintext before encryption)
        SSLSocket.getOutputStream.implementation = function() {
            var outputStream = this.getOutputStream();
            var remoteAddress = this.getRemoteSocketAddress().toString();
            
            console.log("[*] SSLSocket.getOutputStream() called for: " + remoteAddress);
            
            // Wrap OutputStream to capture write operations
            var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            var captureBuffer = ByteArrayOutputStream.$new();
            
            var originalWrite1 = outputStream.write.overload('int');
            var originalWrite2 = outputStream.write.overload('[B');
            var originalWrite3 = outputStream.write.overload('[B', 'int', 'int');
            var originalFlush = outputStream.flush;
            
            // Capture single byte writes
            outputStream.write.overload('int').implementation = function(b) {
                captureBuffer.write(b);
                return originalWrite1.call(this, b);
            };
            
            // Capture byte array writes
            outputStream.write.overload('[B').implementation = function(b) {
                captureBuffer.write(b);
                return originalWrite2.call(this, b);
            };
            
            // Capture byte array writes with offset/length
            outputStream.write.overload('[B', 'int', 'int').implementation = function(b, off, len) {
                captureBuffer.write(b, off, len);
                return originalWrite3.call(this, b, off, len);
            };
            
            // Capture on flush
            outputStream.flush.implementation = function() {
                if (captureBuffer.size() > 0) {
                    var capturedBytes = captureBuffer.toByteArray();
                    
                    // Try to parse as UTF-8 text (HTTP)
                    try {
                        var text = Java.use("java.lang.String").$new(capturedBytes, "UTF-8");
                        var textStr = text.toString();
                        
                        if (textStr.indexOf('POST ') === 0 || textStr.indexOf('GET ') === 0 || textStr.indexOf('PUT ') === 0) {
                            sendData('https', 'HTTPS_REQUEST', {
                                protocol: 'SSLSocket-HTTP',
                                remote_address: remoteAddress,
                                body: textStr.substring(0, Math.min(textStr.length, 10000)),
                                body_length: capturedBytes.length
                            });
                            console.log("[+] SSLSocket HTTP request captured: " + capturedBytes.length + " bytes to " + remoteAddress);
                        }
                    } catch (e) {
                        // Binary data (Protocol Buffers, gRPC, etc.)
                        var hexPreview = '';
                        for (var i = 0; i < Math.min(capturedBytes.length, 100); i++) {
                            var b = capturedBytes[i] & 0xFF;
                            hexPreview += ('0' + b.toString(16)).slice(-2) + ' ';
                        }
                        
                        sendData('https', 'HTTPS_REQUEST', {
                            protocol: 'SSLSocket-Binary',
                            remote_address: remoteAddress,
                            binary_size: capturedBytes.length,
                            hex_preview: hexPreview,
                            raw_bytes: Array.from(capturedBytes.slice(0, 200))
                        });
                        console.log("[+] SSLSocket BINARY request captured: " + capturedBytes.length + " bytes (likely protobuf/gRPC) to " + remoteAddress);
                    }
                    
                    // Reset buffer for next request
                    captureBuffer.reset();
                }
                
                return originalFlush.call(this);
            };
            
            return outputStream;
        };
        
        // Hook getInputStream to capture HTTPS responses
        SSLSocket.getInputStream.implementation = function() {
            var inputStream = this.getInputStream();
            var remoteAddress = this.getRemoteSocketAddress().toString();
            
            console.log("[*] SSLSocket.getInputStream() called for: " + remoteAddress);
            
            var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            var captureBuffer = ByteArrayOutputStream.$new();
            
            var originalRead1 = inputStream.read.overload();
            var originalRead2 = inputStream.read.overload('[B');
            var originalRead3 = inputStream.read.overload('[B', 'int', 'int');
            
            // Capture single byte reads
            inputStream.read.overload().implementation = function() {
                var b = originalRead1.call(this);
                if (b !== -1) {
                    captureBuffer.write(b);
                } else if (captureBuffer.size() > 0) {
                    // End of stream, send captured data
                    this._sendCapturedResponse(remoteAddress, captureBuffer);
                }
                return b;
            };
            
            // Capture byte array reads
            inputStream.read.overload('[B').implementation = function(b) {
                var bytesRead = originalRead2.call(this, b);
                if (bytesRead > 0) {
                    captureBuffer.write(b, 0, bytesRead);
                } else if (bytesRead === -1 && captureBuffer.size() > 0) {
                    this._sendCapturedResponse(remoteAddress, captureBuffer);
                }
                return bytesRead;
            };
            
            // Capture byte array reads with offset/length
            inputStream.read.overload('[B', 'int', 'int').implementation = function(b, off, len) {
                var bytesRead = originalRead3.call(this, b, off, len);
                if (bytesRead > 0) {
                    var tempArray = b.slice(off, off + bytesRead);
                    captureBuffer.write(tempArray, 0, bytesRead);
                } else if (bytesRead === -1 && captureBuffer.size() > 0) {
                    this._sendCapturedResponse(remoteAddress, captureBuffer);
                }
                return bytesRead;
            };
            
            // Helper to send captured response
            inputStream._sendCapturedResponse = function(remoteAddress, captureBuffer) {
                var capturedBytes = captureBuffer.toByteArray();
                
                try {
                    var text = Java.use("java.lang.String").$new(capturedBytes, "UTF-8");
                    var textStr = text.toString();
                    
                    if (textStr.indexOf('HTTP/') === 0) {
                        sendData('https', 'HTTPS_RESPONSE', {
                            protocol: 'SSLSocket-HTTP',
                            remote_address: remoteAddress,
                            body: textStr.substring(0, Math.min(textStr.length, 10000)),
                            body_length: capturedBytes.length
                        });
                        console.log("[+] SSLSocket HTTP response captured: " + capturedBytes.length + " bytes from " + remoteAddress);
                    }
                } catch (e) {
                    var hexPreview = '';
                    for (var i = 0; i < Math.min(capturedBytes.length, 100); i++) {
                        var b = capturedBytes[i] & 0xFF;
                        hexPreview += ('0' + b.toString(16)).slice(-2) + ' ';
                    }
                    
                    sendData('https', 'HTTPS_RESPONSE', {
                        protocol: 'SSLSocket-Binary',
                        remote_address: remoteAddress,
                        binary_size: capturedBytes.length,
                        hex_preview: hexPreview,
                        raw_bytes: Array.from(capturedBytes.slice(0, 200))
                    });
                    console.log("[+] SSLSocket BINARY response captured: " + capturedBytes.length + " bytes (likely protobuf/gRPC) from " + remoteAddress);
                }
                
                captureBuffer.reset();
            };
            
            return inputStream;
        };
        
        hookedAPIs.https.push("SSLSocket Streams (" + hookedClass + ")");
        console.log("[+] SSLSocket stream hooks installed on " + hookedClass + " (Conscrypt - captures Firebase protobuf!)");
        
    } catch (e) {
        console.log("[-] Error hooking SSLSocket streams: " + e);
        console.log("[-] Stack trace: " + e.stack);
    }
}

/**
 * Hook Network APIs (basic monitoring, not full HTTPS)
 */
function hookNetworkAPIs() {
    try {
        // HttpURLConnection - basic connect monitoring
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        HttpURLConnection.connect.implementation = function() {
            var url = this.getURL().toString();
            sendData("network", "HTTP_CONNECT", {
                url: url,
                method: this.getRequestMethod()
            });
            return this.connect();
        };
        
        hookedAPIs.network.push("HttpURLConnection.connect");
        
        // URL.openConnection
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            sendData("network", "URL_OPEN_CONNECTION", {
                url: this.toString()
            });
            return this.openConnection();
        };
        
        hookedAPIs.network.push("URL.openConnection");
        
        console.log("[+] Network APIs hooked");
        
    } catch (e) {
        console.log("[-] Error hooking network APIs: " + e);
    }
}

/**
 * Hook File I/O APIs
 */
function hookFileAPIs() {
    try {
        // FileOutputStream
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        
        FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
            sendData("file", "FILE_WRITE", {
                path: path,
                operation: "open_for_write"
            });
            return this.$init(path);
        };
        
        FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
            sendData("file", "FILE_WRITE", {
                path: file.getAbsolutePath(),
                operation: "open_for_write"
            });
            return this.$init(file);
        };
        
        hookedAPIs.file.push("FileOutputStream");
        
        // FileInputStream
        var FileInputStream = Java.use("java.io.FileInputStream");
        
        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            sendData("file", "FILE_READ", {
                path: path,
                operation: "open_for_read"
            });
            return this.$init(path);
        };
        
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            sendData("file", "FILE_READ", {
                path: file.getAbsolutePath(),
                operation: "open_for_read"
            });
            return this.$init(file);
        };
        
        hookedAPIs.file.push("FileInputStream");
        
        // File.delete
        var File = Java.use("java.io.File");
        File.delete.implementation = function() {
            sendData("file", "FILE_DELETE", {
                path: this.getAbsolutePath()
            });
            return this.delete();
        };
        
        hookedAPIs.file.push("File.delete");
        
        console.log("[+] File I/O APIs hooked");
        
    } catch (e) {
        console.log("[-] Error hooking file APIs: " + e);
    }
}

/**
 * Hook Cryptography APIs
 */
function hookCryptoAPIs() {
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            sendData("crypto", "CIPHER_INIT", {
                transformation: transformation
            });
            return this.getInstance(transformation);
        };
        
        Cipher.doFinal.overload('[B').implementation = function(input) {
            sendData("crypto", "CIPHER_DOFINAL", {
                input_length: input.length,
                algorithm: this.getAlgorithm()
            });
            return this.doFinal(input);
        };
        
        hookedAPIs.crypto.push("Cipher");
        
        // MessageDigest (hashing)
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            sendData("crypto", "HASH_INIT", {
                algorithm: algorithm
            });
            return this.getInstance(algorithm);
        };
        
        hookedAPIs.crypto.push("MessageDigest");
        
        console.log("[+] Crypto APIs hooked");
        
    } catch (e) {
        console.log("[-] Error hooking crypto APIs: " + e);
    }
}

/**
 * Hook SMS APIs
 */
function hookSMSAPIs() {
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        
        SmsManager.sendTextMessage.overload(
            'java.lang.String', 
            'java.lang.String', 
            'java.lang.String', 
            'android.app.PendingIntent', 
            'android.app.PendingIntent'
        ).implementation = function(destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
            sendData("sms", "SEND_SMS", {
                destination: destinationAddress,
                text: text,
                length: text.length
            });
            return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
        };
        
        hookedAPIs.sms.push("SmsManager.sendTextMessage");
        
        console.log("[+] SMS APIs hooked");
        
    } catch (e) {
        console.log("[-] Error hooking SMS APIs: " + e);
    }
}

/**
 * Hook Location APIs
 */
function hookLocationAPIs() {
    try {
        var LocationManager = Java.use("android.location.LocationManager");
        
        LocationManager.requestLocationUpdates.overload(
            'java.lang.String',
            'long',
            'float',
            'android.location.LocationListener'
        ).implementation = function(provider, minTime, minDistance, listener) {
            sendData("location", "REQUEST_LOCATION", {
                provider: provider,
                minTime: minTime,
                minDistance: minDistance
            });
            return this.requestLocationUpdates(provider, minTime, minDistance, listener);
        };
        
        LocationManager.getLastKnownLocation.implementation = function(provider) {
            sendData("location", "GET_LAST_LOCATION", {
                provider: provider
            });
            return this.getLastKnownLocation(provider);
        };
        
        hookedAPIs.location.push("LocationManager");
        
        console.log("[+] Location APIs hooked");
        
    } catch (e) {
        console.log("[-] Error hooking location APIs: " + e);
    }
}

/**
 * Hook Contacts APIs
 */
function hookContactsAPIs() {
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        
        ContentResolver.query.overload(
            'android.net.Uri',
            '[Ljava.lang.String;',
            'java.lang.String',
            '[Ljava.lang.String;',
            'java.lang.String'
        ).implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            sendData("contacts", "QUERY_CONTENT", {
                uri: uri.toString(),
                selection: selection
            });
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
        
        hookedAPIs.contacts.push("ContentResolver.query");
        
        console.log("[+] Contacts APIs hooked");
        
    } catch (e) {
        console.log("[-] Error hooking contacts APIs: " + e);
    }
}

/**
 * Hook Runtime Execution APIs
 */
function hookRuntimeAPIs() {
    try {
        var Runtime = Java.use("java.lang.Runtime");
        
        Runtime.exec.overload('java.lang.String').implementation = function(command) {
            sendData("runtime", "EXEC_COMMAND", {
                command: command
            });
            return this.exec(command);
        };
        
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdarray) {
            sendData("runtime", "EXEC_COMMAND_ARRAY", {
                command: cmdarray.join(' ')
            });
            return this.exec(cmdarray);
        };
        
        hookedAPIs.runtime.push("Runtime.exec");
        
        // ProcessBuilder
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function() {
            sendData("runtime", "PROCESS_START", {
                command: this.command().toString()
            });
            return this.start();
        };
        
        hookedAPIs.runtime.push("ProcessBuilder.start");
        
        console.log("[+] Runtime APIs hooked");
        
    } catch (e) {
        console.log("[-] Error hooking runtime APIs: " + e);
    }
}

/**
 * Hook Dynamic Class Loading
 */
function hookClassLoaderAPIs() {
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        
        DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
            sendData("classloader", "DEX_LOAD", {
                dexPath: dexPath,
                optimizedDirectory: optimizedDirectory,
                librarySearchPath: librarySearchPath
            });
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
        
        hookedAPIs.classLoader.push("DexClassLoader");
        
        // PathClassLoader
        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, parent) {
            sendData("classloader", "PATH_CLASS_LOAD", {
                dexPath: dexPath
            });
            return this.$init(dexPath, parent);
        };
        
        hookedAPIs.classLoader.push("PathClassLoader");
        
        console.log("[+] ClassLoader APIs hooked");
        
    } catch (e) {
        console.log("[-] Error hooking classloader APIs: " + e);
    }
}

/**
 * Hook WebView HTTP/HTTPS requests
 */
function hookWebViewHTTPS() {
    try {
        var WebView = Java.use("android.webkit.WebView");
        
        // Hook loadUrl
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            sendData("https", "WEBVIEW_LOAD_URL", {
                url: url,
                isHTTPS: url.startsWith("https://")
            });
            return this.loadUrl(url);
        };
        
        // Hook loadUrl with headers
        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
            var headerMap = {};
            if (headers) {
                var entrySet = headers.entrySet();
                var iterator = entrySet.iterator();
                while (iterator.hasNext()) {
                    var entry = iterator.next();
                    headerMap[entry.getKey()] = entry.getValue();
                }
            }
            
            sendData("https", "WEBVIEW_LOAD_URL_WITH_HEADERS", {
                url: url,
                headers: headerMap,
                isHTTPS: url.startsWith("https://")
            });
            return this.loadUrl(url, headers);
        };
        
        // Hook postUrl
        WebView.postUrl.overload('java.lang.String', '[B').implementation = function(url, postData) {
            var dataStr = "";
            if (postData) {
                dataStr = bytesToString(postData);
            }
            
            sendData("https", "WEBVIEW_POST_URL", {
                url: url,
                postData: dataStr,
                isHTTPS: url.startsWith("https://")
            });
            return this.postUrl(url, postData);
        };
        
        hookedAPIs.https.push("WebView HTTPS");
        console.log("[+] WebView HTTPS hooks installed");
        
    } catch (e) {
        console.log("[!] WebView not available or hook failed: " + e);
    }
}

/**
 * Main execution - Install all hooks
 */
Java.perform(function() {
    console.log("[*] Starting Enhanced API hooks with HTTPS interception...");
    console.log("[*] Phase 1: Detecting app networking stack...");
    
    // PHASE 1: Detect Cronet (must be done first)
    var hasCronet = detectCronet();
    
    // PHASE 2: Apply SSL unpinning if MITM mode is enabled AND Cronet detected
    if (hasCronet && sslUnpinningEnabled) {
        console.log("[*] Cronet detected + MITM mode enabled: Activating SSL unpinning");
        enableSSLUnpinning();
    } else if (hasCronet) {
        console.log("[!] Cronet detected but MITM mode disabled");
        console.log("[!] HTTPS body capture will be limited to URL metadata");
        console.log("[!] To capture full bodies, rerun with: --mitm-proxy flag");
    }
    
    // PHASE 3: Install HTTPS Interception Hooks
    console.log("[*] Phase 2: Installing HTTPS interception hooks...");
    hookHttpURLConnectionHTTPS();
    hookOkHttpHTTPS();
    
    // Only install SSLSocket hooks if NOT using Cronet (they won't work anyway)
    if (!hasCronet) {
        hookSSLSocketStreams();  // Conscrypt/SSLSocket - for non-Cronet apps
    } else {
        console.log("[!] Skipping SSLSocket hooks (incompatible with Cronet)");
    }
    
    hookWebViewHTTPS();  // WebView support
    
    // PHASE 4: Install Standard API Hooks
    console.log("[*] Phase 3: Installing standard API hooks...");
    hookNetworkAPIs();
    hookFileAPIs();
    hookCryptoAPIs();
    hookSMSAPIs();
    hookLocationAPIs();
    hookContactsAPIs();
    hookRuntimeAPIs();
    hookClassLoaderAPIs();
    
    console.log("[+] All API hooks installed successfully");
    console.log("[*] Hooked APIs summary:");
    console.log(JSON.stringify(hookedAPIs, null, 2));
    
    // Send initialization complete message with Cronet status
    send({
        type: "init_complete",
        hooked_apis: hookedAPIs,
        uses_cronet: hasCronet,
        ssl_unpinning_active: sslUnpinningEnabled
    });
    
    // ========================================================================
    // NATIVE NETWORK HOOKS - THE REAL SOLUTION
    // ========================================================================
    // Load native hooks to capture C++ network traffic (Firebase, Unity, etc.)
    console.log("[*] Loading NATIVE network hooks for C++ traffic...");
    
    setTimeout(function() {
        try {
            // Give app time to load native libraries
            var nativeScript = `
                // Hook at libc socket level
                var sendPtr = Module.findExportByName("libc.so", "send");
                if (sendPtr) {
                    Interceptor.attach(sendPtr, {
                        onEnter: function(args) {
                            var len = args[2].toInt32();
                            if (len > 10 && len < 10000) {  // Capture reasonable size packets
                                try {
                                    // Try reading as UTF-8 first (HTTP)
                                    var data = Memory.readUtf8String(args[1], Math.min(len, 2048));
                                    if (data.indexOf('POST ') === 0 || data.indexOf('GET ') === 0 || data.indexOf('Host:') !== -1) {
                                        send({type: 'native_send', protocol: 'HTTP', data: data.substring(0, 500)});
                                        console.log("[+] Native send() captured HTTP (" + len + " bytes)");
                                    }
                                } catch(e) {
                                    // Not UTF-8, try as binary (Firebase protobuf, etc.)
                                    try {
                                        var buf = Memory.readByteArray(args[1], Math.min(len, 2048));
                                        var hex = '';
                                        var bytes = new Uint8Array(buf);
                                        for (var i = 0; i < Math.min(bytes.length, 100); i++) {
                                            hex += bytes[i].toString(16).padStart(2, '0') + ' ';
                                        }
                                        send({type: 'native_send', protocol: 'BINARY', size: len, hex_preview: hex});
                                        console.log("[+] Native send() captured BINARY (" + len + " bytes) - likely protobuf/gRPC");
                                    } catch(e2) {}
                                }
                            }
                        }
                    });
                    console.log("[+] Hooked libc send() - captures HTTP AND binary (protobuf/gRPC)");
                }
                
                // Hook SSL_write for HTTPS plaintext (HTTP AND binary protocols like gRPC/protobuf)
                var SSL_write = Module.findExportByName("libssl.so", "SSL_write") || Module.findExportByName("libboringssl.so", "SSL_write");
                if (SSL_write) {
                    Interceptor.attach(SSL_write, {
                        onEnter: function(args) {
                            var len = args[2].toInt32();
                            if (len > 10 && len < 50000) {  // Increased limit for large payloads
                                try {
                                    // Try HTTP first
                                    var data = Memory.readUtf8String(args[1], Math.min(len, 2048));
                                    if (data.indexOf('POST ') === 0 || data.indexOf('GET ') === 0 || data.indexOf('HTTP/') !== -1) {
                                        send({type: 'SSL_write', protocol: 'HTTP', data: data.substring(0, 1000)});
                                        console.log("[+] SSL_write HTTP (" + len + " bytes)");
                                    }
                                } catch(e) {
                                    // Binary protocol (Firebase protobuf, gRPC, etc.)
                                    try {
                                        var buf = Memory.readByteArray(args[1], Math.min(len, 2048));
                                        var hex = '';
                                        var bytes = new Uint8Array(buf);
                                        
                                        // Show first 100 bytes in hex
                                        for (var i = 0; i < Math.min(bytes.length, 100); i++) {
                                            hex += bytes[i].toString(16).padStart(2, '0') + ' ';
                                        }
                                        
                                        // Try to detect protocol
                                        var protocol = 'BINARY';
                                        if (bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x00) {
                                            protocol = 'gRPC/HTTP2';
                                        }
                                        
                                        send({
                                            type: 'SSL_write',
                                            protocol: protocol,
                                            size: len,
                                            hex_preview: hex,
                                            raw_bytes: Array.from(bytes.slice(0, 200))  // First 200 bytes for analysis
                                        });
                                        console.log("[+] SSL_write " + protocol + " (" + len + " bytes) - Firebase/protobuf");
                                    } catch(e2) {
                                        console.log("[-] SSL_write capture failed: " + e2);
                                    }
                                }
                            }
                        }
                    });
                    console.log("[+] Hooked SSL_write() - HTTP + Binary (gRPC/protobuf)");
                }
            `;
            
            eval(nativeScript);
            console.log("[+] Native hooks active - will capture C++ network traffic!");
        } catch (e) {
            console.log("[-] Native hooks failed: " + e);
        }
    }, 2000);  // Wait 2 seconds for native libraries to load
});
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
