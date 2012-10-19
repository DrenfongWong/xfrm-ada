with Ada.Streams;

with Anet.Sockets.Netlink;

package Xfrm.Sockets
is

   type Xfrm_Socket_Type is new
     Anet.Sockets.Netlink.Raw_Socket_Type with private;
   --  Netlink/XFRM socket.

   procedure Init (Socket : in out Xfrm_Socket_Type);
   --  Initialize given XFRM socket.

   procedure Send_Ack
     (Socket : Xfrm_Socket_Type;
      Item   : Ada.Streams.Stream_Element_Array);
   --  Send given data to the XFRM subsystem, wait for ACK from the kernel.
   --  Raises an exception if the result was not OK.

   procedure Add_Policy
     (Socket : Xfrm_Socket_Type;
      Src    : Anet.IPv4_Addr_Type;
      Dst    : Anet.IPv4_Addr_Type;
      Reqid  : Positive);
   --  Add XFRM policy.

   procedure Delete_Policy
     (Socket : Xfrm_Socket_Type;
      Src    : Anet.IPv4_Addr_Type;
      Dst    : Anet.IPv4_Addr_Type);
   --  Delete XFRM policy.

   Xfrm_Error : exception;

private

   type Xfrm_Socket_Type is new
     Anet.Sockets.Netlink.Raw_Socket_Type with null record;

end Xfrm.Sockets;
