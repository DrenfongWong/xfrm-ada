with System;

with Interfaces.C.Strings;
with Interfaces.C.Extensions;

with Anet.Constants;

with xfrm_h;

with Xfrm.Thin;

package body Xfrm.Sockets
is

   function C_Strerror
     (Errnum : Interfaces.C.int)
      return Interfaces.C.Strings.chars_ptr;
   pragma Import (C, C_Strerror, "strerror");

   procedure C_Memcpy
     (Dst : System.Address;
      Src : System.Address;
      Len : Interfaces.C.size_t);
   pragma Import (C, C_Memcpy, "memcpy");

   XFRM_INF : constant Interfaces.C.Extensions.unsigned_long_long := not 0;

   -------------------------------------------------------------------------

   procedure Add_Policy
     (Socket : Xfrm_Socket_Type;
      Src    : Anet.IPv4_Addr_Type;
      Dst    : Anet.IPv4_Addr_Type;
      Reqid  : Positive)
   is
      use Xfrm.Thin;
      use type Interfaces.Unsigned_16;
      use type Interfaces.Unsigned_32;

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
   begin

      --  HDR

      Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
      Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_NEWPOLICY);
      Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
        (Nlmsg_Length (Len => xfrm_h.xfrm_userpolicy_info'Object_Size / 8));

      --  Policy

      C_Memcpy (Dst => Policy.sel.saddr.a4'Address,
                Src => Src'Address,
                Len => Src'Length);
      C_Memcpy (Dst => Policy.sel.daddr.a4'Address,
                Src => Dst'Address,
                Len => Dst'Length);
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

      Tmpl.reqid    := Interfaces.C.unsigned (Reqid);
      Tmpl.id.proto := Anet.Constants.IPPROTO_ESP;
      Tmpl.aalgos   := not 0;
      Tmpl.ealgos   := not 0;
      Tmpl.calgos   := not 0;
      Tmpl.mode     := XFRM_MODE_TRANSPORT;
      Tmpl.family   := 2;

      Socket.Send_Ack (Item => Buffer (Buffer'First ..
                         Ada.Streams.Stream_Element_Offset (Hdr.Nlmsg_Len)));
   end Add_Policy;

   -------------------------------------------------------------------------

   procedure Delete_Policy
     (Socket : Xfrm_Socket_Type;
      Src    : Anet.IPv4_Addr_Type;
      Dst    : Anet.IPv4_Addr_Type)
   is
      use Xfrm.Thin;
      use type Interfaces.Unsigned_16;

      Buffer : Ada.Streams.Stream_Element_Array (1 .. 512) := (others => 0);
      Hdr    : aliased Nlmsghdr_Type;
      for Hdr'Address use Buffer'Address;

      Policy_Id_Addr : constant System.Address := Nlmsg_Data
        (Msg => Hdr'Access);
      Policy_Id      : xfrm_h.xfrm_userpolicy_id;
      for Policy_Id'Address use Policy_Id_Addr;
      pragma Import (Ada, Policy_Id);
   begin

      --  HDR

      Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
      Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_DELPOLICY);
      Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
        (Nlmsg_Length (Len => xfrm_h.xfrm_userpolicy_id'Object_Size / 8));

      --  Policy ID

      C_Memcpy (Dst => Policy_Id.sel.saddr.a4'Address,
                Src => Src'Address,
                Len => Src'Length);
      C_Memcpy (Dst => Policy_Id.sel.daddr.a4'Address,
                Src => Dst'Address,
                Len => Dst'Length);
      Policy_Id.sel.family      := 2;
      Policy_Id.sel.prefixlen_d := 32;
      Policy_Id.sel.prefixlen_s := 32;

      Socket.Send_Ack (Item => Buffer (Buffer'First ..
                         Ada.Streams.Stream_Element_Offset (Hdr.Nlmsg_Len)));
   end Delete_Policy;

   -------------------------------------------------------------------------

   procedure Init (Socket : in out Xfrm_Socket_Type)
   is
   begin
      Anet.Sockets.Netlink.Raw_Socket_Type (Socket).Init
        (Protocol => Anet.Sockets.Netlink.Proto_Netlink_Xfrm);
   end Init;

   -------------------------------------------------------------------------

   procedure Send_Ack
     (Socket : Xfrm_Socket_Type;
      Item   : Ada.Streams.Stream_Element_Array)
   is
      use type Interfaces.Unsigned_16;

      Buffer : Ada.Streams.Stream_Element_Array (1 .. 1024);
      Last   : Ada.Streams.Stream_Element_Offset;
   begin
      Socket.Send (Item);
      Socket.Receive (Item => Buffer,
                      Last => Last);

      declare
         Recv_Buffer : Ada.Streams.Stream_Element_Array
           := Buffer (Buffer'First .. Last);
         Recv_Hdr    : aliased Xfrm.Thin.Nlmsghdr_Type;
         for Recv_Hdr'Address use Recv_Buffer'Address;
      begin
         if not Xfrm.Thin.Nlmsg_Ok
           (Msg => Recv_Hdr,
            Len => Natural (Last))
         then
            raise Xfrm_Error with "Invalid reply from kernel";
         end if;

         if Recv_Hdr.Nlmsg_Type = Xfrm.Thin.NLMSG_ERROR then
            declare
               use type Interfaces.C.int;

               Err_Addr : constant System.Address
                 := Xfrm.Thin.Nlmsg_Data (Msg => Recv_Hdr'Access);
               Err      : Xfrm.Thin.Nlmsgerr_Type;
               for Err'Address use Err_Addr;
            begin
               if Err.Error /= 0 then
                  raise Xfrm_Error with Interfaces.C.Strings.Value
                    (C_Strerror (Errnum => -Err.Error));
               else

                  --  OK.

                  return;
               end if;
            end;
         else
            raise Xfrm_Error with "Request not acknowledged";
         end if;
      end;
   end Send_Ack;

end Xfrm.Sockets;
