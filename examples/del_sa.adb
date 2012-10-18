with Ada.Text_IO;
with Ada.Streams;

with System;

with Interfaces.C;

with Anet.Constants;

with xfrm_h;

with Xfrm.Sockets;

procedure Del_Sa
is

   use type Interfaces.Unsigned_16;

   subtype Netlink_Buffer_Type is Ada.Streams.Stream_Element_Array (1 .. 512);

   Buffer : Netlink_Buffer_Type := (others => 0);
   Hdr    : aliased Xfrm.Nlmsghdr_Type;
   for Hdr'Address use Buffer'Address;

   Sa_Id_Addr : constant System.Address
     := Xfrm.Nlmsg_Data (Msg => Hdr'Access);
   Sa_Id      : xfrm_h.xfrm_usersa_id;
   for Sa_Id'Address use Sa_Id_Addr;
   pragma Import (Ada, Sa_Id);

   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin

   --  HDR

   Hdr.Nlmsg_Flags := Xfrm.NLM_F_REQUEST or Xfrm.NLM_F_ACK;
   Hdr.Nlmsg_Type  := Xfrm.Xfrm_Msg_Type'Enum_Rep (Xfrm.XFRM_MSG_DELSA);
   Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
     (Xfrm.Nlmsg_Length (Len => xfrm_h.xfrm_usersa_id'Object_Size / 8));

   --  SA ID

   Sa_Id.daddr.a4 := 1007640728;
   Sa_Id.proto    := Anet.Constants.IPPROTO_ESP;
   Sa_Id.spi      := 123;
   Sa_Id.family   := 2;

   Sock.Init;
   Sock.Bind (Address => 0);
   Sock.Send_Ack (Item => Buffer
                  (Buffer'First .. Ada.Streams.Stream_Element_Offset
                     (Hdr.Nlmsg_Len)));
   Ada.Text_IO.Put_Line ("OK");
end Del_Sa;
