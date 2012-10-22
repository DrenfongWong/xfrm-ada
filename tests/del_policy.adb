with Ada.Text_IO;

with Xfrm.Sockets;

procedure Del_Policy
is
   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin
   Sock.Init;
   Sock.Delete_Policy (Src       => (192, 168, 1, 1),
                       Dst       => (192, 168, 2, 1),
                       Direction => Xfrm.Sockets.Direction_Out);
   Ada.Text_IO.Put_Line ("OK");
end Del_Policy;
