module:    dylan-user
author:    Hannes Mehnert
copyright: Original Code is Copyright (c) 2010 Dylan Hackers;
           All rights reversed.
License:   See License.txt in this distribution for details.
Warranty:  Distributed WITHOUT WARRANTY OF ANY KIND

define library ssl
  use common-dylan;
  use c-ffi;
  use io;
  use system, import: { file-system };
  use network;
  export
    openssl-wrapper,
    ssl-sockets;
end library;

define module openssl-wrapper
  use dylan;
  use c-ffi;
  use unix-sockets, import: { <c-buffer-offset> };
  export
    ssl-library-init,
    ssl-load-error-strings,
    err-load-bio-strings,
    rand-load-file;
  export
    ssl-new,
    ssl-read,
    ssl-write,
    ssl-shutdown,
    ssl-get-fd,
    ssl-set-fd,
    ssl-connect,
    ssl-accept,
    ssl-get-error;
  export
    err-get-error,
    err-error-string;
  export
    tls-method,
    tls-server-method,
    tls-client-method;
  export
    <ssl-ctx>,
    ssl-context-new,
    ssl-context-free,
    ssl-free,
    ssl-context-use-certificate-file,
    ssl-context-use-private-key-file;
  export
    <x509>,
    <x509**>,
    x509-new;
  export
    $ssl-mode-auto-retry,
    $ssl-filetype-pem;
  export
    $ssl-error-none,
    $ssl-error-ssl,
    $ssl-error-want-read,
    $ssl-error-want-write,
    $ssl-error-want-x509-lookup,
    $ssl-error-syscall,
    $ssl-error-zero-return,
    $ssl-error-want-connect,
    $ssl-error-want-accept;
  export
    ssl-set-mode,
    pem-read-x509,
    ssl-context-add-extra-chain-certificate,
    ssl-set-tlsext-host-name;
end module;

define module ssl-sockets
  use byte-storage;
  use c-ffi;
  use common-dylan;
  use file-system, import: { file-exists?, file-property, <pathname> };
  use machine-words;
  use openssl-wrapper;
  use sockets;
  use streams-internals;
  use threads;
  use unix-sockets, import: { errno };

  export
    <ssl-socket>,
    start-tls;
  export
    <ssl-failure>,
    <pem-file-failure>,
    <pem-file-not-available>,
    <pem-file-not-readable>,
    <error-reading-pem-file>,
    <x509-failure>,
    <ssl-error>,
    <err-error>;
  export
    // TODO(cgay): exporting this from ssl-sockets for now, but we may ultimately want to
    // have separate modules for sockets and crypto and I'm not sure where this should
    // ultimately end up yet.
    read-pem-file;
end module;
