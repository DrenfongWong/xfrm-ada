with Ada.Text_IO;
with Ada.Streams;

with System;

with Interfaces.C;
with Interfaces.C.Extensions;

with Anet.Constants;

with xfrm_h;

with Xfrm.Thin;
with Xfrm.Sockets;

procedure Add_Policy
is
   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin
   Sock.Init;
   Sock.Add_Policy
     (Src   => (192, 168, 1, 1),
      Dst   => (192, 168, 2, 1),
      Reqid => 1);
   Ada.Text_IO.Put_Line ("OK");
end Add_Policy;
