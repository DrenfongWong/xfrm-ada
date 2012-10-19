with Ada.Text_IO;

with Xfrm.Sockets;

procedure Flush_Policies
is
   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin
   Sock.Init;
   Sock.Flush_Policies;
   Ada.Text_IO.Put_Line ("OK");
end Flush_Policies;
