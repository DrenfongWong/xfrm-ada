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

   use Xfrm.Thin;
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;

   XFRM_INF : constant Interfaces.C.Extensions.unsigned_long_long := not 0;

   Buffer : Ada.Streams.Stream_Element_Array (1 .. 512) := (others => 0);
   Hdr    : aliased Nlmsghdr_Type;
   for Hdr'Address use Buffer'Address;

   Policy_Addr : constant System.Address := Nlmsg_Data (Msg => Hdr'Access);
   Policy      : xfrm_h.xfrm_userpolicy_info;
   for Policy'Address use Policy_Addr;
   pragma Import (Ada, Policy);

   Rta_Addr : constant System.Address
     := Nlmsg_Data (Msg => Hdr'Access,
                    Len => xfrm_h.xfrm_userpolicy_info'Object_Size / 8);
   Rta      : aliased Rtattr_Type;
   for Rta'Address use Rta_Addr;

   Tmpl_Addr : constant System.Address
     := Rta_Data (Rta => Rta'Access);
   Tmpl      : xfrm_h.xfrm_user_tmpl;
   for Tmpl'Address use Tmpl_Addr;
   pragma Import (Ada, Tmpl);

   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin

   --  HDR

   Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
   Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_NEWPOLICY);
   Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
     (Nlmsg_Length (Len => xfrm_h.xfrm_userpolicy_info'Object_Size / 8));

   --  Policy

   Policy.sel.saddr.a4    := 537878680;
   Policy.sel.daddr.a4    := 1007640728;
   Policy.sel.family      := 2;
   Policy.sel.prefixlen_d := 32;
   Policy.sel.prefixlen_s := 32;
   Policy.priority        := 3843;
   Policy.action          := XFRM_POLICY_ALLOW;
   Policy.share           := Xfrm_Share_Type'Pos (XFRM_SHARE_ANY);

   Policy.lft.soft_byte_limit   := XFRM_INF;
   Policy.lft.soft_packet_limit := XFRM_INF;
   Policy.lft.hard_byte_limit   := XFRM_INF;
   Policy.lft.hard_packet_limit := XFRM_INF;

   --  RTA

   Rta.Rta_Type  := xfrm_h.xfrm_attr_type_t'Pos (xfrm_h.XFRMA_TMPL);
   Rta.Rta_Len   := Interfaces.C.unsigned_short
     (Rta_Length (Len => xfrm_h.xfrm_user_tmpl'Object_Size / 8));
   Hdr.Nlmsg_Len := Hdr.Nlmsg_Len + Interfaces.Unsigned_32
     (Align (Len => Positive (Rta.Rta_Len)));

   --  Template

   Tmpl.reqid    := 1;
   Tmpl.id.proto := Anet.Constants.IPPROTO_ESP;
   Tmpl.aalgos   := not 0;
   Tmpl.ealgos   := not 0;
   Tmpl.calgos   := not 0;
   Tmpl.mode     := XFRM_MODE_TRANSPORT;
   Tmpl.family   := 2;

   Sock.Init;
   Sock.Bind (Address => 0);
   Sock.Send_Ack (Item => Buffer
                  (Buffer'First .. Ada.Streams.Stream_Element_Offset
                     (Hdr.Nlmsg_Len)));
   Ada.Text_IO.Put_Line ("OK");
end Add_Policy;
