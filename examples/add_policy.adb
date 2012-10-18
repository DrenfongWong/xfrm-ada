with Ada.Text_IO;
with Ada.Streams;

with System;

with Interfaces.C.Strings;
with Interfaces.C.Extensions;

with Anet.Constants;
with Anet.Sockets.Netlink;

with xfrm_h;

with Xfrm.Sockets;

procedure Add_Policy
is

   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;

   subtype Netlink_Buffer_Type is Ada.Streams.Stream_Element_Array (1 .. 512);

   XFRM_INF : constant Interfaces.C.Extensions.unsigned_long_long := not 0;

   Send_Buffer : Netlink_Buffer_Type := (others => 0);
   Send_Hdr    : aliased Xfrm.Nlmsghdr_Type;
   for Send_Hdr'Address use Send_Buffer'Address;

   Policy_Addr : constant System.Address
     := Xfrm.Nlmsg_Data (Msg => Send_Hdr'Access);
   Policy      : xfrm_h.xfrm_userpolicy_info;
   for Policy'Address use Policy_Addr;
   pragma Import (Ada, Policy);

   Rta_Addr : constant System.Address
     := Xfrm.Nlmsg_Data
       (Msg => Send_Hdr'Access,
        Len => xfrm_h.xfrm_userpolicy_info'Object_Size / 8);
   Rta      : aliased Xfrm.Rtattr_Type;
   for Rta'Address use Rta_Addr;

   Tmpl_Addr : constant System.Address
     := Xfrm.Rta_Data (Rta => Rta'Access);
   Tmpl      : xfrm_h.xfrm_user_tmpl;
   for Tmpl'Address use Tmpl_Addr;
   pragma Import (Ada, Tmpl);

   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin

   --  HDR

   Send_Hdr.Nlmsg_Flags := Xfrm.NLM_F_REQUEST or Xfrm.NLM_F_ACK;
   Send_Hdr.Nlmsg_Type  := Xfrm.Xfrm_Msg_Type'Enum_Rep
     (Xfrm.XFRM_MSG_NEWPOLICY);
   Send_Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
     (Xfrm.Nlmsg_Length (Len => xfrm_h.xfrm_userpolicy_info'Object_Size / 8));

   --  Policy

   Policy.sel.saddr.a4    := 537878680;
   Policy.sel.daddr.a4    := 1007640728;
   Policy.sel.family      := 2;
   Policy.sel.prefixlen_d := 32;
   Policy.sel.prefixlen_s := 32;
   Policy.priority        := 3843;
   Policy.action          := Xfrm.XFRM_POLICY_ALLOW;
   Policy.share           := Xfrm.Xfrm_Share_Type'Pos (Xfrm.XFRM_SHARE_ANY);

   Policy.lft.soft_byte_limit   := XFRM_INF;
   Policy.lft.soft_packet_limit := XFRM_INF;
   Policy.lft.hard_byte_limit   := XFRM_INF;
   Policy.lft.hard_packet_limit := XFRM_INF;

   --  RTA

   Rta.Rta_Type := xfrm_h.xfrm_attr_type_t'Pos (xfrm_h.XFRMA_TMPL);
   Rta.Rta_Len  := Interfaces.C.unsigned_short
     (Xfrm.Rta_Length (Len => xfrm_h.xfrm_user_tmpl'Object_Size / 8));

   Send_Hdr.Nlmsg_Len := Send_Hdr.Nlmsg_Len + Interfaces.Unsigned_32
     (Xfrm.Align (Len => Xfrm.Rta_Length
                  (Len => xfrm_h.xfrm_user_tmpl'Object_Size / 8)));

   --  Template

   Tmpl.reqid    := 1;
   Tmpl.id.proto := Anet.Constants.IPPROTO_ESP;
   Tmpl.aalgos   := not 0;
   Tmpl.ealgos   := not 0;
   Tmpl.calgos   := not 0;
   Tmpl.mode     := Xfrm.XFRM_MODE_TRANSPORT;
   Tmpl.family   := 2;

   Sock.Init (Protocol => Anet.Sockets.Netlink.Proto_Netlink_Xfrm);
   Sock.Bind (Address => 0);
   Sock.Send_Ack (Item => Send_Buffer
                  (Send_Buffer'First .. Ada.Streams.Stream_Element_Offset
                     (Send_Hdr.Nlmsg_Len)));
   Ada.Text_IO.Put_Line ("OK");
end Add_Policy;