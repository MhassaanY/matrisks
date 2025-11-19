/**
 * Frida Hook Script - API Monitor
 * Monitors sensitive Android APIs for dynamic analysis
 */

console.log("[*] API Monitor script loaded");

// Track hooked APIs
var hookedAPIs = {
    network: [],
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
        details: details,
        stacktrace: getStackTrace()
    });
}

/**
 * Get call stack trace
 */
function getStackTrace() {
    return Java.use("android.util.Log").getStackTraceString(
        Java.use("java.lang.Exception").$new()
    );
}

/**
 * Hook Network APIs
 */
function hookNetworkAPIs() {
    try {
        // HttpURLConnection
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
        
        // OkHttp3
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var Request = Java.use("okhttp3.Request");
            
            OkHttpClient.newCall.implementation = function(request) {
                var url = request.url().toString();
                var method = request.method();
                
                sendData("network", "OKHTTP_REQUEST", {
                    url: url,
                    method: method,
                    headers: request.headers().toString()
                });
                
                return this.newCall(request);
            };
            
            hookedAPIs.network.push("OkHttpClient.newCall");
        } catch (e) {
            console.log("[-] OkHttp not found: " + e);
        }
        
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
 * Main execution
 */
Java.perform(function() {
    console.log("[*] Starting API hooks...");
    
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
    
    // Send initialization complete message
    send({
        type: "init_complete",
        hooked_apis: hookedAPIs
    });
});
