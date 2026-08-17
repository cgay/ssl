Module: dylan-user

define library ssl-test-suite
  use common-dylan;
  use testworks;
  use ssl;
end library;

define module ssl-test-suite
  use common-dylan;
  use openssl-wrapper;
  use ssl-sockets;
  use testworks;
end module;
