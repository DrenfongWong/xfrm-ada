with Ada.Text_IO;

with Xfrm.Sockets;

procedure Flush_States
is
   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin
   Sock.Init;
   Sock.Flush_States;
   Ada.Text_IO.Put_Line ("OK");
end Flush_States;
