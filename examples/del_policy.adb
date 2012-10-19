with Ada.Text_IO;
with Ada.Streams;

with System;

with Interfaces.C;

with xfrm_h;

with Xfrm.Thin;
with Xfrm.Sockets;

procedure Del_Policy
is

   use Xfrm.Thin;
   use type Interfaces.Unsigned_16;

   Buffer : Ada.Streams.Stream_Element_Array (1 .. 512) := (others => 0);
   Hdr    : aliased Nlmsghdr_Type;
   for Hdr'Address use Buffer'Address;

   Policy_Id_Addr : constant System.Address := Nlmsg_Data (Msg => Hdr'Access);
   Policy_Id      : xfrm_h.xfrm_userpolicy_id;
   for Policy_Id'Address use Policy_Id_Addr;
   pragma Import (Ada, Policy_Id);

   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin

   --  HDR

   Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
   Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_DELPOLICY);
   Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
     (Nlmsg_Length (Len => xfrm_h.xfrm_userpolicy_id'Object_Size / 8));

   --  Policy ID

   Policy_Id.sel.saddr.a4    := 537878680;
   Policy_Id.sel.daddr.a4    := 1007640728;
   Policy_Id.sel.family      := 2;
   Policy_Id.sel.prefixlen_d := 32;
   Policy_Id.sel.prefixlen_s := 32;

   Sock.Init;
   Sock.Bind (Address => 0);
   Sock.Send_Ack (Item => Buffer
                  (Buffer'First .. Ada.Streams.Stream_Element_Offset
                     (Hdr.Nlmsg_Len)));
   Ada.Text_IO.Put_Line ("OK");
end Del_Policy;
