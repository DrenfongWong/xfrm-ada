with Ada.Text_IO;
with Ada.Streams;

with System;

with Interfaces.C;

with xfrm_h;

with Xfrm.Sockets;

procedure Del_Policy
is

   use type Interfaces.Unsigned_16;

   subtype Netlink_Buffer_Type is Ada.Streams.Stream_Element_Array (1 .. 512);

   Send_Buffer : Netlink_Buffer_Type := (others => 0);
   Send_Hdr    : aliased Xfrm.Nlmsghdr_Type;
   for Send_Hdr'Address use Send_Buffer'Address;

   Policy_Id_Addr : constant System.Address
     := Xfrm.Nlmsg_Data (Msg => Send_Hdr'Access);
   Policy_Id      : xfrm_h.xfrm_userpolicy_id;
   for Policy_Id'Address use Policy_Id_Addr;
   pragma Import (Ada, Policy_Id);

   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin

   --  HDR

   Send_Hdr.Nlmsg_Flags := Xfrm.NLM_F_REQUEST or Xfrm.NLM_F_ACK;
   Send_Hdr.Nlmsg_Type  := Xfrm.Xfrm_Msg_Type'Enum_Rep
     (Xfrm.XFRM_MSG_DELPOLICY);
   Send_Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
     (Xfrm.Nlmsg_Length (Len => xfrm_h.xfrm_userpolicy_id'Object_Size / 8));

   --  Policy ID

   Policy_Id.sel.saddr.a4    := 537878680;
   Policy_Id.sel.daddr.a4    := 1007640728;
   Policy_Id.sel.family      := 2;
   Policy_Id.sel.prefixlen_d := 32;
   Policy_Id.sel.prefixlen_s := 32;

   Sock.Init;
   Sock.Bind (Address => 0);
   Sock.Send_Ack (Item => Send_Buffer
                  (Send_Buffer'First .. Ada.Streams.Stream_Element_Offset
                     (Send_Hdr.Nlmsg_Len)));
   Ada.Text_IO.Put_Line ("OK");
end Del_Policy;
