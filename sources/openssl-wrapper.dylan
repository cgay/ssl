Module:    ssl-sockets
synopsis:  ssl support for sockets
author:    Hannes Mehnert
copyright: Original Code is Copyright (c) 2010 Dylan Hackers;
           All rights reversed.
License:   See License.txt in this distribution for details.
Warranty:  Distributed WITHOUT WARRANTY OF ANY KIND

//define function init-ssl ()
begin
  ssl-library-init();
  ssl-load-error-strings();
  err-load-bio-strings();
  //OpenSSL-add-all-algorithms();
  //XXX: hardcoded random device. this is probably bad
  rand-load-file("/dev/urandom", 2048);
end;

define constant $null-pointer = null-pointer(<c-void*>);

define class <ssl-failure> (<socket-error>) end;

// TODO(cgay): This is in no way a socket error; rework the class hierarchy.
define class <pem-file-failure> (<ssl-failure>) end;

define class <pem-file-not-available> (<pem-file-failure>) end;

define class <pem-file-not-readable> (<pem-file-failure>) end;

define class <error-reading-pem-file> (<pem-file-failure>) end;

define class <x509-failure> (<ssl-failure>) end;

define function read-pem-file (filename :: <pathname>) => (result :: <x509>)
  unless (file-exists?(filename))
    signal(make(<pem-file-not-available>,
                format-string: "pem file not found: %s",
                format-arguments: list(filename)))
  end;
  unless (file-property(filename, #"readable?"))
    signal(make(<pem-file-not-readable>,
                format-string: "pem file not readable: %s",
                format-arguments: list(filename)))
  end;
  let x = x509-new(); //need to manually free the X509 struct?
  if (null-pointer?(x))
    let e = err-error();
    signal(make(<x509-failure>, format-string: "%s", format-arguments: e))
  else
    let ret = pem-read-x509(as(<byte-string>, filename),
                            c-pointer-at(<x509**>, x),
                            $null-pointer, $null-pointer);
    if (null-pointer?(ret))
      signal(make(<x509-failure>,
                  format-string: "pem file failed to load: %s",
                  format-arguments: list(filename)))
    else
      ret
    end
  end
end function;

define abstract class <ssl-socket> (<tcp-socket>)
  constant slot underlying-socket :: <socket>, init-keyword: lower:;
  slot ssl-context :: <ssl-ctx>;
end class;

define method make
    (class == <ssl-socket>, #rest initargs, #key element-type = <byte-character>)
 => (stream :: <ssl-socket>)
  apply(make, client-class-for-element-type(class, element-type), initargs)
end method;

define method local-port (s :: <ssl-socket>) => (port :: <integer>)
  s.underlying-socket.local-port
end method;

define method local-host (s :: <ssl-socket>) => (host :: <internet-address>)
  s.underlying-socket.local-host
end method;

define method remote-host (s :: <ssl-socket>) => (host :: <internet-address>)
  s.underlying-socket.remote-host
end method;

define method remote-port (s :: <ssl-socket>) => (port :: <integer>)
  s.underlying-socket.remote-port
end method;

define method client-class-for-element-type
    (class == <ssl-socket>, element-type == <byte>) => (class == <byte-ssl-socket>)
  <byte-ssl-socket>
end method;

define method client-class-for-element-type
    (class == <ssl-socket>, element-type == <byte-character>)
 => (class == <byte-char-ssl-socket>)
  <byte-char-ssl-socket>
end method;

define method client-class-for-element-type
    (class == <ssl-socket>, element-type :: <type>) => (class == <general-ssl-socket>)
  <general-ssl-socket>
end method;

define class <general-ssl-socket> (<ssl-socket>, <general-typed-stream>)
  inherited slot stream-element-type = <character>;
end class;

define class <byte-char-ssl-socket> (<ssl-socket>, <general-typed-stream>)
  inherited slot stream-element-type = <byte-character>;
end class;

define class <byte-ssl-socket> (<ssl-socket>, <general-typed-stream>)
  inherited slot stream-element-type = <byte>;
end class;

define class <ssl-error> (<ssl-failure>) end;
define class <err-error> (<ssl-failure>) end;

define method initialize
    (sock :: <ssl-socket>, #rest rest,
     #key lower, requested-buffer-size, acc?, #all-keys)
 => ()
  let keys = list(#"port", lower.remote-port,
                  #"host", lower.remote-host,
                  #"direction", lower.stream-direction);
  apply(next-method, sock, keys);
  // TODO(cgay): instead of passing `acc?: #t` when creating a server-side client socket,
  // make a <ssl-client-socket> class?
  unless (acc?) //not a server socket via accept
    //already setup a connection! do SSL handshake over this connection
    let ctx = ssl-context-new(tls-client-method());
    if (null-pointer?(ctx))
      err-error();
    end;
    sock.ssl-context := ctx;
    let ssl = ssl-new(sock.ssl-context);
    if (null-pointer?(ssl))
      err-error();
    end;
    // always set sni
    ssl-set-tlsext-host-name(ssl, host-name(remote-host(sock)));
    sock.accessor.socket-descriptor := ssl;
    let r = ssl-set-fd(ssl, lower.accessor.socket-descriptor);
    if (r ~= 1)
      ssl-error(ssl, r);
    end;
    ssl-set-mode(ssl, $ssl-mode-auto-retry);
    let ret = ssl-connect(sock.accessor.socket-descriptor); //does the handshake
    if (ret == 0)
      close(lower);
      ssl-error(ssl, ret);
    elseif (ret < 0)
      close(lower);
      ssl-error(ssl, ret);
    end
  end
end method initialize;

// TODO(cgay): it's odd that this is a subclass of <tcp-server-socket> and yet
// `make(class == <tcp-server-socket>, ssl?: #t, ...)` makes BOTH a <tcp-server-socket>
// AND an <ssl-server-socket>.  Surely we can just make an <ssl-server-socket>?
define class <ssl-server-socket> (<tcp-server-socket>)
  constant slot underlying-socket :: <server-socket>, init-keyword: lower:;
  slot ssl-context :: <ssl-ctx>;
  constant slot starttls? :: <boolean> = #f, init-keyword: starttls?:;
end class;

define class <unix-ssl-socket-accessor> (<unix-socket-accessor>)
end class;

define method initialize
    (socket :: <ssl-server-socket>, #rest rest,
     #key certificate, key, certificate-chain, #all-keys)
 => ()
  let ctx = ssl-context-new(tls-server-method());
  if (null-pointer?(ctx))
    err-error();
  end;
  socket.ssl-context := ctx;
  unless (file-exists?(certificate))
    signal(make(<pem-file-not-available>))
  end;
  unless (file-property(as(<pathname>, certificate), #"readable?"))
    signal(make(<pem-file-not-readable>))
  end;
  let r = ssl-context-use-certificate-file(socket.ssl-context, certificate,
                                           $ssl-filetype-pem);
  if (r ~= 1)
    err-error();
  end;
  unless (file-exists?(key))
    signal(make(<pem-file-not-available>))
  end;
  unless (file-property(as(<pathname>, key), #"readable?"))
    signal(make(<pem-file-not-readable>))
  end;
  let r = ssl-context-use-private-key-file(socket.ssl-context, key,
                                           $ssl-filetype-pem);
  if (r ~= 1)
    err-error();
  end;
  if (certificate-chain)
    let cas = if (instance?(certificate-chain, <string>))
                list(certificate-chain)
              else
                certificate-chain
              end;
    let rs = map(curry(ssl-context-add-extra-chain-certificate, socket.ssl-context),
                 map(read-pem-file, cas));
    if (any?(curry(\~=, 1), rs))
      err-error();
    end
  end;
  socket.socket-descriptor := socket.underlying-socket.socket-descriptor;
end method initialize;

define method accept
    (server-socket :: <ssl-server-socket>, #rest args, #key element-type = #f, #all-keys)
 => (connected-socket :: <socket>)
  let manager = current-socket-manager();
  let lower-socket = server-socket.underlying-socket;
  let descriptor = accessor-accept(lower-socket);
  let result =
    with-lock (socket-manager-lock(manager))
      let lower = apply(make,
                        client-class-for-server(lower-socket),
                        descriptor: descriptor,
                        element-type: element-type | lower-socket.default-element-type,
                        args);
      if (server-socket.starttls?)
        lower
      else
        block()
          start-tls(server-socket, lower)
        exception (s :: type-union(<err-error>, <ssl-error>))
          close(lower);
          #f;
        end;
      end;
    end with-lock;
  result | apply(accept, server-socket, args)
end method;

define method start-tls (server-socket :: <ssl-server-socket>, client :: <tcp-socket>)
 => (ssl-socket :: false-or(<ssl-socket>))
  let ssl = ssl-new(server-socket.ssl-context);
  if (null-pointer?(ssl))
    err-error();
  end;
  let r = ssl-set-fd(ssl, client.socket-descriptor);
  if (r ~= 1)
    ssl-error(ssl, r);
  end;
  ssl-set-mode(ssl, $ssl-mode-auto-retry);
  let s = ssl-accept(ssl);
  if (s == 0)
    ssl-error(ssl, s);
  elseif (s < 0)
    ssl-error(ssl, s);
  end;
  let acc = make(<unix-ssl-socket-accessor>);
  acc.socket-descriptor := ssl;
  make(client-class-for-server(server-socket),
       lower: client,
       accessor: acc,
       descriptor: ssl,
       element-type: server-socket.underlying-socket.default-element-type,
       acc?: #t)
end;

define function err-error (#key prefix = "") => ()
  let eerr = err-get-error();
  let mess = copy-sequence(as(<byte-string>, err-error-string(eerr, $null-pointer)));
  signal(make(<err-error>, format-string: "%s %s", format-arguments: list(prefix, mess)));
end;

define function ssl-error (ssl, r) => ()
  let err = ssl-get-error(ssl, r);
  if (err == $ssl-error-ssl)
    err-error(prefix: "received ssl error");
  elseif (err == $ssl-error-syscall)
    signal(make(<ssl-error>,
                format-string: "received syscall error %d while calling openssl",
                format-arguments: list(errno())));
  end;
  let description
    = select (err)
        $ssl-error-none => "no error"; // ??
        $ssl-error-ssl => "SSL error";
        $ssl-error-want-read => "WANT READ";
        $ssl-error-want-write => "WANT WRITE";
        $ssl-error-want-x509-lookup => "WANT X509 LOOKUP";
        $ssl-error-syscall => "SYSCALL error";
        $ssl-error-zero-return => "ZERO RETURN";
        $ssl-error-want-connect => "WANT CONNECT";
        $ssl-error-want-accept => "WANT ACCEPT";
        otherwise => "unknown error";
      end;
  signal(make(<ssl-error>,
              format-string: "%d %s",
              format-arguments: list(err, description)))
end function;

define method close
    (the-socket :: <ssl-server-socket>,
     #rest keys,
     #key abort? = #f, wait? = #t, synchronize? = #f,
          already-unregistered? = #f)
 => ()
  ssl-context-free(the-socket.ssl-context);
  close(the-socket.underlying-socket);
  the-socket.socket-descriptor := #f;
end;

define method accessor-read-into!
    (accessor :: <unix-ssl-socket-accessor>, stream :: <platform-socket>,
     offset :: <buffer-index>, count :: <buffer-index>,
     #key buffer)
 => (nread :: <integer>)
  let the-buffer = buffer | stream-input-buffer(stream);
  with-object-byte-storage (buffer-storage-address = the-buffer)
    let r
      = interruptible-system-call
          (ssl-read(accessor.socket-descriptor,
                    u%+(buffer-storage-address, offset),
                    count));
    if (r < 0)
      ssl-error(accessor.socket-descriptor, r);
    end;
    r
  end
end;

define method accessor-write-from
    (accessor :: <unix-ssl-socket-accessor>, stream :: <platform-socket>,
     offset :: <buffer-index>, count :: <buffer-index>,
     #key buffer, return-fresh-buffer?)
 => (nwritten :: <integer>, new-buffer :: <buffer>)
  let buffer = buffer | stream-output-buffer(stream);
  with-object-byte-storage (buffer-storage-address = buffer)
    let nwritten
      = interruptible-system-call
          (ssl-write(accessor.socket-descriptor,
                     u%+(buffer-storage-address, offset),
                     count));
    if (nwritten < 0)
      ssl-error(accessor.socket-descriptor, nwritten);
    end;
    values(nwritten, buffer)
  end
end;

define method accessor-close
    (accessor :: <unix-ssl-socket-accessor>, #key abort?, wait?)
 => (closed? :: <boolean>)
  let ssl* = accessor.socket-descriptor;
  let s = ssl-shutdown(ssl*);
  /* according to documentation, shutdown only half-done,
     and SSL-shutdown should be called again.
     but, calling ssl-shutdown again sends data; and when
     the other side has quit (eg openssl s_client with ctrl+c)
     this results in bus errors... */
//  if (s == 0)
//    let s = SSL-shutdown(ssl*);
//    if (s ~= 1)
//      SSL-error(ssl*, s);
//    end
//  elseif (s < 0)
  if (s < 0)
    ssl-error(ssl*, s);
  end;
  let real-fd = ssl-get-fd(ssl*);
  if (real-fd == -1)
    ssl-error(ssl*, real-fd);
  end;
  ssl-free(ssl*);
  accessor.socket-descriptor := #f;
  accessor-close-socket(real-fd);
  #t
end;

define method accessor-open
    (accessor :: <unix-ssl-socket-accessor>, locator, #rest rest,
     #key remote-host, remote-port, descriptor, no-delay?, direction,
          if-exists, if-does-not-exist,
     #all-keys)
 => ()
  if (descriptor)
    //this is a connected socket returned by accept
    accessor.socket-descriptor := descriptor;
  end;
end;

define method client-class-for-server
    (server :: <ssl-server-socket>) => (res == <ssl-socket>)
  <ssl-socket>
end;

define method type-for-socket (s :: <ssl-socket>) => (res == #"ssl")
  #"ssl"
end;

define sideways method platform-accessor-class
    (type == #"ssl", locator) => (class == <unix-ssl-socket-accessor>)
  ignore(locator);
  <unix-ssl-socket-accessor>
end method;

define sideways method ssl-socket-class
    (class == <tcp-socket>) => (ssl-class == <ssl-socket>)
  <ssl-socket>
end;

define sideways method ssl-server-socket-class
    (class == <tcp-server-socket>) => (ssl-server-class == <ssl-server-socket>)
  <ssl-server-socket>
end;
