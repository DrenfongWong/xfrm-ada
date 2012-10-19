with Ada.Text_IO;
with Ada.Streams;

with System;

with Interfaces.C;

with Anet.Constants;

with xfrm_h;

with Xfrm.Thin;
with Xfrm.Sockets;

procedure Del_Sa
is
   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin
   Sock.Init;
   Sock.Delete_State (Dst => (192, 168, 2, 1),
                      Spi => 123);

   Ada.Text_IO.Put_Line ("OK");
end Del_Sa;
