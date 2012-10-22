with Ada.Streams;

with Anet.Sockets.Netlink;

package Xfrm.Sockets
is

   type Direction_Type is
     (Direction_In,
      Direction_Fwd,
      Direction_Out);
   --  Policy directions.

   type Xfrm_Socket_Type is new
     Anet.Sockets.Netlink.Raw_Socket_Type with private;
   --  Netlink/XFRM socket.

   procedure Init (Socket : in out Xfrm_Socket_Type);
   --  Initialize given XFRM socket.

   procedure Send_Ack
     (Socket     : Xfrm_Socket_Type;
      Err_Prefix : String;
      Item       : Ada.Streams.Stream_Element_Array);
   --  Send given data to the XFRM subsystem, wait for ACK from the kernel.
   --  Raises an exception with specified error message prefix if the operation
   --  was not successful.

   procedure Add_Policy
     (Socket    : Xfrm_Socket_Type;
      Src       : Anet.IPv4_Addr_Type;
      Dst       : Anet.IPv4_Addr_Type;
      Reqid     : Positive;
      Direction : Direction_Type);
   --  Add XFRM policy with given parameters.

   procedure Delete_Policy
     (Socket    : Xfrm_Socket_Type;
      Src       : Anet.IPv4_Addr_Type;
      Dst       : Anet.IPv4_Addr_Type;
      Direction : Direction_Type);
   --  Delete XFRM policy.

   procedure Flush_Policies (Socket : Xfrm_Socket_Type);
   --  Flush SPD.

   procedure Add_State
     (Socket        : Xfrm_Socket_Type;
      Src           : Anet.IPv4_Addr_Type;
      Dst           : Anet.IPv4_Addr_Type;
      Reqid         : Positive;
      Spi           : Positive;
      Enc_Key       : Anet.Byte_Array;
      Enc_Alg       : String;
      Int_Key       : Anet.Byte_Array;
      Int_Alg       : String;
      Lifetime_Soft : Interfaces.Unsigned_64 := 0;
      Lifetime_Hard : Interfaces.Unsigned_64 := 0);
   --  Add SA with given parameters. The lifetime parameters specify the amount
   --  in seconds of the soft/hard expire timeout of the SA; the default is 0
   --  (= no timeout).

   procedure Delete_State
     (Socket : Xfrm_Socket_Type;
      Dst    : Anet.IPv4_Addr_Type;
      Spi    : Positive);
   --  Delete SA state with given parameters.

   procedure Flush_States (Socket : Xfrm_Socket_Type);
   --  Flush SAD.

   Xfrm_Error : exception;

private

   type Xfrm_Socket_Type is new
     Anet.Sockets.Netlink.Raw_Socket_Type with null record;

end Xfrm.Sockets;
