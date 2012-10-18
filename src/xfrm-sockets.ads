with Ada.Streams;

with Anet.Sockets.Netlink;

package Xfrm.Sockets
is

   type Xfrm_Socket_Type is new
     Anet.Sockets.Netlink.Raw_Socket_Type with private;
   --  Netlink/XFRM socket.

   procedure Send_Ack
     (Socket : Xfrm_Socket_Type;
      Item   : Ada.Streams.Stream_Element_Array);
   --  Send given data to the XFRM subsystem, wait for ACK from the kernel.
   --  Raises an exception if the result was not OK.

   Xfrm_Error : exception;

private

   type Xfrm_Socket_Type is new
     Anet.Sockets.Netlink.Raw_Socket_Type with null record;

end Xfrm.Sockets;
